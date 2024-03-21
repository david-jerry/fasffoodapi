from rest_framework import pagination
from rest_framework.response import Response

class CustomPagination(pagination.PageNumberPagination):
    """
    # Custom DRF Pagination
    Custom pagination class for controlling page size and formatting paginated responses.

    Attributes:
        `page_size (int)`: Number of items per page.
        `page_size_query_param (str)`: Query parameter to specify page size.
        `max_page_size (int)`: Maximum allowed page size.
        `page_query_param (str)`: Query parameter to specify page number.

    ## Example Usage:
    ```python
    class MyViewSet(viewsets.ModelViewSet):
        `pagination_class = CustomPagination`

        queryset = MyModel.objects.all()
        serializer_class = MyModelSerializer
    ```
    """

    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 500
    page_query_param = 'p'

    def get_paginated_response(self, data):
        """
        Return a paginated style `Response` object for the given output data.

        Args:
            `data (list)`: List of serialized objects.

        Returns:
            `Response`: Paginated response containing the serialized data along with pagination information.
        """
        response = Response(data)
        response['count'] = self.page.paginator.count
        response['next'] = self.get_next_link()
        response['previous'] = self.get_previous_link()
        return response
