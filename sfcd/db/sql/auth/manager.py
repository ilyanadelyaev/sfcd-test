import sfcd.db.sql.base

import sfcd.db.sql.auth.simple
import sfcd.db.sql.auth.facebook


class Manager(sfcd.db.sql.base.ManagerBase):
    """
    Process all auth models in one manager
    """

    def __init__(self, *args, **kwargs):
        super(Manager, self).__init__(*args, **kwargs)
        # add some import magic her
        self.simple = sfcd.db.sql.auth.simple.SimpleMethod(self)
        self.facebook = sfcd.db.sql.auth.facebook.FacebookMethod(self)
