# Generated by Django 4.1 on 2023-11-29 20:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("DocOrgnizer", "0007_remove_userprofile_confirmation_token_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="confirmation_token",
            field=models.CharField(blank=True, max_length=32, null=True),
        ),
        migrations.AlterField(
            model_name="userprofile",
            name="is_active",
            field=models.BooleanField(default=False),
        ),
    ]
