# -*- coding: utf-8 -*-
# Generated by Django 1.10b1 on 2017-01-17 10:39
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('StaticAnalyzer', '0002_staticanalyzerioszip_permissions'),
    ]

    operations = [
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='BIN_ANALYSIS',
            field=models.TextField(default=[]),
            preserve_default=False,
        ),
    ]
