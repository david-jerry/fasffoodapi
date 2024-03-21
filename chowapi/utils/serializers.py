from rest_framework import serializers


# class FieldErrorSerializer(serializers.Serializer):
#     """
#     Serializer for a single field error.
#     """
#     field = serializers.CharField()
#     error_message = serializers.CharField()


# class FieldsErrorsSerializer(serializers.Serializer):
#     """
#     Serializer for multiple field errors.
#     """
#     errors = serializers.ListField(child=FieldErrorSerializer())


# class CustomErrorSerializer(serializers.Serializer):
#     """
#     Serializer for custom error messages, handling both single error messages
#     and multiple field errors.
#     """
#     error_code = serializers.CharField()
#     error_message = serializers.SerializerMethodField()

#     def get_error_message(self, obj):
#         """
#         Retrieve the error message based on the object type.
#         """
#         if isinstance(obj, dict):
#             # Single error message
#             return obj.get('error_message', '')
#         elif isinstance(obj, list):
#             # Multiple field errors
#             return FieldsErrorsSerializer(obj).data
#         else:
#             return ''



# from rest_framework import serializers


class FieldErrorSerializer(serializers.Serializer):
    """
    Serializer for field error.
    """
    field = serializers.CharField()
    error_message = serializers.CharField()


class CustomErrorSerializer(serializers.Serializer):
    error_code = serializers.CharField()
    error_message = FieldErrorSerializer(many=True)
