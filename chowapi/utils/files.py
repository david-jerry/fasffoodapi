import calendar
import os
import time

PROFILE_IMAGE_UPLOAD_PATH = "uploads/profile"
SHOP_LOGO_IMAGE_UPLOAD_PATH = "uploads/vendors"
FOOD_IMAGE_UPLOAD_PATH = "uploads/vendors/food"
STATIC_IMAGE_UPLOAD_PATH = "uploads/static"

class FileUploader:
    """Helper class for handling file uploads.

    Example:
        To use this class for uploading an image in a Django model::
            ```python
            class YourModel(models.Model):
                profile_image = models.ImageField(
                    upload_to=FILEUPLOAD.profile_image_upload_path
                )
                vendor_logo_image = models.ImageField(
                    upload_to=FILEUPLOAD.vendor_logo_image_upload_path
                )
                food_image = models.ImageField(
                    upload_to=FILEUPLOAD.food_image_upload_path
                )
                static_image = models.ImageField(
                    upload_to=FILEUPLOAD.static_image_upload_path
                )
                # Other fields in your model
            ```

    Attributes:
        `PROFILE_IMAGE_UPLOAD_PATH (str)`: The base path for profile image uploads.
        `SHOP_LOGO_IMAGE_UPLOAD_PATH (str)`: The base path for vendor logo image uploads.
        `FOOD_IMAGE_UPLOAD_PATH (str)`: The base path for food image uploads.
        `STATIC_IMAGE_UPLOAD_PATH (str)`: The base path for static image uploads.

    Methods:
        `profile_image_upload_path(instance, filename)`:
            Returns the path for profile image upload.
        `vendor_logo_image_upload_path(instance, filename)`:
            Returns the path for vendor logo image upload.
        `food_image_upload_path(instance, filename)`:
            Returns the path for food image upload.
        `static_image_upload_path(instance, filename)`:
            Returns the path for static image upload.

    """

    @staticmethod
    def _file_upload(instance, path, filename):
        """Change file name and set the upload path.

        Args:
            instance (QuerySet): QuerySet instance of the image to be uploaded.
            filename (str): Filename string.
            path (str): Path for file upload.

        Returns:
            str: The path for file upload.
        """
        timestamp = calendar.timegm(time.gmtime())
        ext = filename.split(".")[-1]
        if instance.id:
            filename = "%s/%s" % (instance.id, timestamp)
        else:
            filename = "%s" % timestamp
        filename = f"{filename}.{ext}"
        return os.path.join(path, filename)

    def profile_image_upload_path(self, instance, filename):
        """Returns the path for profile image upload.

        Args:
            instance (QuerySet): QuerySet instance of the image to be uploaded.
            filename (str): Filename string.

        Returns:
            str: The path for profile image upload.
        """
        return self._file_upload(instance, PROFILE_IMAGE_UPLOAD_PATH, filename)

    def vendor_logo_image_upload_path(self, instance, filename):
        """Returns the path for vendor logo image upload.

        Args:
            instance (QuerySet): QuerySet instance of the image to be uploaded.
            filename (str): Filename string.

        Returns:
            str: The path for vendor logo image upload.
        """
        return self._file_upload(instance, SHOP_LOGO_IMAGE_UPLOAD_PATH, filename)

    def food_image_upload_path(self, instance, filename):
        """Returns the path for food image upload.

        Args:
            instance (QuerySet): QuerySet instance of the image to be uploaded.
            filename (str): Filename string.

        Returns:
            str: The path for food image upload.
        """
        return self._file_upload(instance, FOOD_IMAGE_UPLOAD_PATH, filename)

    def static_image_upload_path(self, instance, filename):
        """Returns the path for static image upload.

        Args:
            instance (QuerySet): QuerySet instance of the image to be uploaded.
            filename (str): Filename string.

        Returns:
            str: The path for static image upload.
        """
        return self._file_upload(instance, STATIC_IMAGE_UPLOAD_PATH, filename)


FILEUPLOAD = FileUploader()
