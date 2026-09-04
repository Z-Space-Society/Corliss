"""The app's form classes.

Both are rendered as `{{ form }}` and nothing else: Django's own div renderer
emits a label, the errors and the widget per field, and `.stacked-form` in
base.css is what makes that markup wear this site's clothes. No per-field HTML
in any template, and no partial to keep in step with two pages.

The console's controls stay hand-written and stay that way. A row-form is an
action and an identifier in a table cell, which is not what a form class is for;
these two are text a person types into a model, which is exactly what it is for.
"""

from django import forms

from corliss.models import User, Workspace


class StackedForm(forms.ModelForm):
    """A form rendered one field above the next, with no label suffix.

    Django appends ":" to every label by default. That reads as a prompt on a
    line of prose and as noise above a box, and nothing else on this site puts
    one there.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("label_suffix", "")
        super().__init__(*args, **kwargs)


class AccountForm(StackedForm):
    """The member's own name and email.

    Blank is allowed on both and is a real answer rather than an omission: it
    re-arms `views._upsert_member`'s fill, so the next login takes the PDS's
    value again. Both fields are `blank=True` on the model, so the form asks for
    neither, and that is the behaviour rather than an oversight.

    Clearing `email_confirmed` when the address changes is the view's job, not
    this form's: it is a side effect on a third field that the member cannot see
    or set, and `views.account` saves with `update_fields` for that reason.
    """

    class Meta:
        model = User
        fields = ["display_name", "email"]
        # `display_name` would auto-label as "Display name" and `email` as
        # "Email address", which is `AbstractUser`'s verbose name. Both are
        # longer than the thing they sit above needs.
        labels = {"display_name": "Name", "email": "Email"}
        widgets = {
            "display_name": forms.TextInput(
                attrs={"placeholder": "how you'd like to be listed"}
            ),
            "email": forms.EmailInput(attrs={"placeholder": "you@example.com"}),
        }
        error_messages = {
            "email": {"invalid": "That is not an email address."},
        }


class WorkspaceForm(StackedForm):
    """A workspace's name and description.

    A `ModelForm` where the rest of this app hand-parses `request.POST`, because
    these are the first fields that are text a person types into a model rather
    than an action and an identifier. The length limit, the required-ness and the
    redisplay-with-errors on a failed save all come from the model instead of
    from three hand-written checks that can drift from it.

    There is deliberately no `clean_name` guarding against a name of spaces.
    `CharField` strips before it checks `required`, so "   " arrives as "" and is
    refused as empty; a hand-written check for it could never fire.
    """

    class Meta:
        model = Workspace
        fields = ["name", "description"]
        widgets = {
            "name": forms.TextInput(
                attrs={"placeholder": "what this group of people is working on"}
            ),
            "description": forms.Textarea(
                attrs={
                    "rows": 4,
                    "placeholder": "optional: what happens here, and who it's for",
                }
            ),
        }
