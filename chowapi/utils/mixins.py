from __future__ import unicode_literals, absolute_import

import csv
from django.http import HttpResponse
from django.core.exceptions import PermissionDenied

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

class ExportMixin:
    def __init__(self):
        pass

    def export_as_csv(self, request, queryset):
        if not request.user.is_staff:
            raise PermissionDenied

        meta = self.model._meta
        field_names = [field.name for field in meta.fields]

        response = HttpResponse(content="text/csv")
        response["Content-Disposition"] = f"attachment; filename={meta}.csv"
        writer = csv.writer(response)

        writer.writerow(field_names)
        for obj in queryset:
            row = writer.writerow([getattr(obj, field) for field in field_names])

        return response

    export_as_csv.short_description = "Export Selected Fields as CSV"


    def export_as_pdf(self, request, queryset):
        if not request.user.is_staff:
            raise PermissionDenied

        meta = self.model._meta
        field_names = [field.name for field in meta.fields]

        response = HttpResponse(content_type="application/pdf")
        response["Content-Disposition"] = f"attachment; filename={meta}.pdf"

        c = canvas.Canvas(response, pagesize=letter)
        c.drawString(100, 750, "PDF Export Example")  # Customize your PDF content here

        for obj in queryset:
            for field in field_names:
                value = getattr(obj, field)
                c.drawString(100, 700, f"{field}: {value}")

        c.showPage()
        c.save()

        return response

    export_as_pdf.short_description = "Export Selected Fields as PDF"


EXPORTMIXIN = ExportMixin()
