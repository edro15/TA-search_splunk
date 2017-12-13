
# encoding = utf-8

def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example gets the alert action parameters and prints them to the log
    splunk_search = helper.get_param("splunk_search")
    helper.log_info("splunk_search={}".format(splunk_search))

    search_description = helper.get_param("search_description")
    helper.log_info("search_description={}".format(search_description))

    index = helper.get_param("index")
    helper.log_info("index={}".format(index))

    search_timeout = helper.get_param("search_timeout")
    helper.log_info("search_timeout={}".format(search_timeout))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="splunk_search")
    helper.addevent("world", sourcetype="splunk_search")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    helper.log_info("Alert action splunk_search started.")
    import splunk.rest
    import json
    import time
    import re
    
    search_timeout = helper.get_param("search_timeout")
    splunk_search = helper.get_param("splunk_search")
    search_description = helper.get_param("search_description")
    index_name = helper.get_param("index")
    
    #Check Splunk Search does not have single quotes
    pattern=re.compile("\'")
    if pattern.match(splunk_search):
            helper.log_error('Single quote detected in Splunk search string, use double quotes instead')
            
    
    #Check Splunk Search Description is only alpha numeric chars, commas and fullstops
    #pattern=re.compile("[\w\,\.\s]+")
    #if not pattern.match(search_description):
    #    helper.log_error('Search description has invalid characters.  Only spaces, commas, fullstops and alphanumeric characters')
    
    runSearch = "/servicesNS/nobody/TA-splunk-search-ar/search/jobs?output_mode=json&count=-1"
    pollSearch = "/servicesNS/nobody/TA-splunk-search-ar/search/jobs/"
    #Create an empty dict to hold POST args/user input
    
    
    helper.log_info("Gathering contextual search data")
    for single_search in splunk_search.split("#"):
        pdata = {}
        #add this to our post data for the splunk search
        pdata = {'search': single_search}
        
        #make the search request to the Splunk REST endpoint
        head, content = splunk.rest.simpleRequest(runSearch, sessionKey=helper.settings["session_key"], postargs=pdata, method='POST')
        
        #get our search ID/sid
        data = json.loads(content)
        
        time_limit = 120
        current_time = 0
        
        isDone = False
        #poll the search endpoint until the search is done
        while not isDone:
            head, content = splunk.rest.simpleRequest(pollSearch + data['sid'] + "?output_mode=json", sessionKey=helper.settings["session_key"], method='GET')
            status = json.loads(content)
            if status['entry'][0]['content']['isDone']:
                isDone = True
            else:
                time.sleep(1)

            current_time += 1
            if current_time > time_limit:
                break
    
        head, content = splunk.rest.simpleRequest(pollSearch + data['sid'] + "/results?output_mode=json", sessionKey=helper.settings["session_key"], method='GET')
    
        #load the search results (json array)
        searches_to_run = {}
        earlier_offset = {}
        later_offset = {}
        fields_required = {}
        
        contextual_search_data = json.loads(content)
        contextual_search_data['description'] = search_description
     
       
    
        helper.log_info("Gathering Context")
       
        
        json_results = json.dumps(contextual_search_data)
        helper.addevent(str(json_results), sourcetype="ar_search")
    #Write results to adaptive index.    
    helper.writeevents(index=index_name, host="splunk_server", source="adaptive_response_search")
    
        # TODO: Implement your alert action logic here
        
