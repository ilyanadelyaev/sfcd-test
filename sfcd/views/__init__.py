from . import auth


def register_views(app):
    """
    views register magic
    """
    for v in (auth, ):
        v.register_view(app)
