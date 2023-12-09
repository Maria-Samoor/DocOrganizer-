# Generated by Django 4.1 on 2023-11-29 19:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("DocOrgnizer", "0006_userprofile_confirmation_token"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="userprofile",
            name="confirmation_token",
        ),
        migrations.AlterField(
            model_name="userprofile",
            name="is_active",
            field=models.BooleanField(
                default=True,
                help_text="Designates whether this user should be treated as active. Unselect this instead of deleting accounts.",
                verbose_name="active",
            ),
        ),
    ]
