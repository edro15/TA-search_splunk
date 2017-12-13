
# encoding = utf-8
# Always put this line at the beginning of this file
import ta_splunk_search_ar_declare

import os
import sys

from alert_actions_base import ModularAlertBase
import modalert_splunk_search_helper

class AlertActionWorkersplunk_search(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkersplunk_search, self).__init__(ta_name, alert_name)

    def validate_params(self):

        if not self.get_param("splunk_search"):
            self.log_error('splunk_search is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("search_description"):
            self.log_error('search_description is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("search_timeout"):
            self.log_error('search_timeout is a mandatory parameter, but its value is None.')
            return False
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = modalert_splunk_search_helper.process_event(self, *args, **kwargs)
        except (AttributeError, TypeError) as ae:
            self.log_error("Error: {}. Please double check spelling and also verify that a compatible version of Splunk_SA_CIM is installed.".format(ae.message))
            return 4
        except Exception as e:
            msg = "Unexpected error: {}."
            if e.message:
                self.log_error(msg.format(e.message))
            else:
                import traceback
                self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status

if __name__ == "__main__":
    exitcode = AlertActionWorkersplunk_search("TA-splunk-search-ar", "splunk_search").run(sys.argv)
    sys.exit(exitcode)
