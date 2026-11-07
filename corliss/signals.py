"""Keep the sync relay's copy of workspace rosters and members' names current.

The relay checks a workspace's roster beside the `workspaces` claim of a
member's token, and shows members' handles and names beside their notes and
edits. Both copies come from here, pushed through `corliss.sync_relay`.

Receivers rather than calls in the views, so that every path that changes a
roster or a name pushes: the workspace pages, the admin, a shell, a
management command. Two properties have a plausible wrong answer:

- **Pushes run after the transaction commits** (`transaction.on_commit`). A
  rolled-back change never reaches the relay, and a roster push reads the
  roster as committed.
- **A failed push is logged and the save stands.** The relay being down must
  not stop a member being added or a login completing. A missed removal still
  ends when the member's token expires; a missed addition, or a missed name,
  waits for `manage.py sync_relay_rosters`.

What signals cannot see: `QuerySet.update()` and raw SQL send none. Nothing
in Corliss changes these fields that way, and `sync_relay_rosters` repairs
anything that does.
"""

from django.db import transaction
from django.db.models.signals import (
    m2m_changed,
    post_delete,
    post_save,
    pre_delete,
    pre_save,
)
from django.dispatch import receiver

from corliss import sync_relay
from corliss.models import User, Workspace

# The fields of `User` the relay shows.
NAME_FIELDS = {"username", "display_name"}


def _after_commit(push, *args):
    if not sync_relay.is_configured():
        return

    def run():
        try:
            push(*args)
        except sync_relay.SyncRelayError:
            # `sync_relay` has logged it. The save stands; see the module.
            pass

    transaction.on_commit(run)


@receiver(m2m_changed, sender=Workspace.members.through)
def roster_changed(sender, instance, action, reverse, pk_set, **kwargs):
    """Someone joined or left a workspace, from either side of the relation.

    Forward, `instance` is the workspace and `pk_set` its users; reversed
    (`user.workspaces`), `instance` is the user and `pk_set` their workspaces.
    A clear sends no `pk_set`, so which workspaces it touches is read before
    it happens.
    """
    if action == "pre_clear":
        instance._relay_cleared = (
            list(instance.workspaces.values_list("pk", flat=True))
            if reverse
            else [instance.pk]
        )
        return
    if action == "post_clear":
        workspaces = instance.__dict__.pop("_relay_cleared", [])
    elif action in ("post_add", "post_remove") and pk_set:
        workspaces = sorted(pk_set) if reverse else [instance.pk]
    else:
        return
    for pk in workspaces:
        _after_commit(sync_relay.push_workspace_members, pk)


@receiver(post_delete, sender=Workspace)
def workspace_deleted(sender, instance, **kwargs):
    """A deleted workspace's rows go without an `m2m_changed`, and its roster
    is pushed empty."""
    _after_commit(sync_relay.push_workspace_members, instance.pk)


@receiver(pre_delete, sender=User)
def note_users_workspaces(sender, instance, **kwargs):
    instance._relay_workspaces = list(instance.workspaces.values_list("pk", flat=True))


@receiver(post_delete, sender=User)
def user_deleted(sender, instance, **kwargs):
    """A deleted user leaves their workspaces without an `m2m_changed`."""
    for pk in instance.__dict__.pop("_relay_workspaces", []):
        _after_commit(sync_relay.push_workspace_members, pk)


def _names_in_save(update_fields):
    return update_fields is None or bool(NAME_FIELDS & set(update_fields))


@receiver(pre_save, sender=User)
def note_stored_names(sender, instance, update_fields, **kwargs):
    if instance.pk is None or not _names_in_save(update_fields):
        return
    instance._relay_names = (
        User.objects.filter(pk=instance.pk).values_list(*sorted(NAME_FIELDS)).first()
    )


@receiver(post_save, sender=User)
def names_changed(sender, instance, created, update_fields, **kwargs):
    """A member's handle or name changed, or they are new. A save that
    changes neither, such as `touch_last_seen`, pushes nothing."""
    if not _names_in_save(update_fields):
        return
    stored = instance.__dict__.pop("_relay_names", None)
    current = tuple(getattr(instance, field) for field in sorted(NAME_FIELDS))
    if created or stored != current:
        _after_commit(
            sync_relay.push_member,
            instance.did,
            instance.username,
            instance.display_name,
        )
