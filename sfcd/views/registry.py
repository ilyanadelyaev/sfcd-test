from . import auth


def register_views(web_view):
    """
    views register magic
    """
    for v in (auth, ):
        v.register_view(web_view)
