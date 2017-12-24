
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

    host = helper.get_param("host")
    helper.log_info("host={}".format(host))


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
    from datetime import datetime
    
    search_timeout = helper.get_param("search_timeout")
    splunk_search = helper.get_param("splunk_search")
    search_description = helper.get_param("search_description")
    index_name = helper.get_param("index")
    host_name = helper.get_param("host")
    
    #Check Splunk Search does not have single quotes
    pattern=re.compile("\'")
    if pattern.match(splunk_search):
            helper.log_error('Single quote detected in Splunk search string, use double quotes instead')
    
    runSearch = "/servicesNS/nobody/TA-splunk-search-ar/search/jobs?output_mode=json&count=-1"
    pollSearch = "/servicesNS/nobody/TA-splunk-search-ar/search/jobs/"
    
    helper.log_info("Executing searches")
    for single_search in splunk_search.split("#"):
        pdata = {}
        
        #Checks to see if earliest has been set in search field
        if "earliest" not in single_search:
            helper.log_info("Earliest time not specified in search " + str(single_search) + ", defaulting to last 24 hours")
            pdata = {'earliest_time' : '-24h', 'search': single_search}
        else:
            #add this to our post data for the splunk search
            helper.log_info("Earliest time has been specified in search  " + str(single_search) + ", using earliest from search")
            pdata = {'search': single_search}
        
        #make the search request to the Splunk REST endpoint
        head, content = splunk.rest.simpleRequest(runSearch, sessionKey=helper.settings["session_key"], postargs=pdata, method='POST')
        
        #get our search ID/sid
        data = json.loads(content)
        
        #Check current time to create a timer.
        current_time = 0
        
        #Set isDone to False to allow us to move over.
        isDone = False
        
        #Log that search has started.
        helper.log_info("Search of '" + single_search + "' has started")
        
        #poll the search endpoint until the search is done
        while not isDone:
            head, content = splunk.rest.simpleRequest(pollSearch + data['sid'] + "?output_mode=json", sessionKey=helper.settings["session_key"], method='GET')
            #Put the content variable into a dictionary
            
            status = json.loads(content)
            #Check to see if job is done
            if status['entry'][0]['content']['isDone']:
                
                helper.log_info("Search of '" + single_search + "' has completed")
                isDone = True
            else:
                time.sleep(1)

            current_time += 1
            
            #Check to see if the search is timed out
            if current_time > search_timeout:
                helper.log_info("Timed out waiting for search of '" + single_search + "' to complete")
                break
        
        head, content = splunk.rest.simpleRequest(pollSearch + data['sid'] + "/results?output_mode=json", sessionKey=helper.settings["session_key"], method='GET')
        
        #Create Search Data Dictionary
        search_data = {}
        
        #Get the total event count
        eventcount = int(status['entry'][0]['content']['eventCount'])
       
        #Get the earliest time and latest time of event for recording purposes
        earliest = status['entry'][0]['content']['earliestTime']
        
        if "latestTime" in status['entry'][0]['content']:
            latest = status['entry'][0]['content']['latestTime']
        
        else:
            latest = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%L%z')
        
        #Load the results from json array into dictionary
        contextual_search_data = json.loads(content)
        
        #Specify a description field
        contextual_search_data['description'] = search_description
        
        #Create Description Field
        search_data['description'] = search_description
        
        #Create Search Field
        search_data['search'] = single_search
        
        #Specify latest time
        search_data['earliest'] = earliest
        #Write the latest time in the search results
        search_data['latest'] = str(latest)
        
        #Check to see if there is any results field and if not create an empty one
        if contextual_search_data['results']:
            search_data['results'] = contextual_search_data['results']
        else:
            search_data['results'] = "None"
        
        #Check to see if there is any messages field and if not create an empty one    
        if contextual_search_data['messages']:
            search_data['messages'] = contextual_search_data['messages']
        else:
            search_data['messages'] = "None"
        #If there are no events in the results log a message    
        if eventcount == 0:
            helper.log_info("Search of '" + str(single_search) + "' returned " + str(eventcount) + " results") 
       
        json_results = json.dumps(search_data)
        
        #Add event to output
        helper.addevent(str(json_results), sourcetype="ar:search")
    
    #Write results to adaptive index.    
    helper.writeevents(index=index_name, host=host_name, source="adaptive_response_search")
    
        # TODO: Implement your alert action logic here
        
