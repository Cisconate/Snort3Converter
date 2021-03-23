import re
from unidecode import unidecode
import argparse
import time
import logging

logging.basicConfig(filename="snortconverterlog.txt", level=logging.DEBUG)

global sid_start_selector
global keyword_tracker
global converted_list
global row_tracker


# Helper Function takes Field Agent Keyword and unknown number of associated fields then converts them to Snort 3
def convert_threshold_snort3(threshold_list):
    # Count fields so you know how many to add to list
    temp = []
    temp2 = threshold_list[0].split(":")
    # Manually write modified threshold-->event_filter field
    temp.append("event_filter:")
    # Skip threshold field and add additional fields if they exist
    temp.append(temp2[1])
    temp.append(";")
    return temp


# Helper Function takes Field Agent Keyword and unknown number of associated fields then converts them to Snort 3
def convert_dns_query_snort3(dns_query_list):
    # First run will have only one Content field so we need to accommodate secondary and tertiary runs
    # Count fields so you know how many to add to list
    global converted_list
    global row_tracker
    temp = []
    temp3 = []

    # Manually write modified byte_test field to test for DNS traffic instead of dns.query
    temp.append("byte_test:1,!&,0xF8,2;")
    # Add first content field to temp list
    temp3.append(dns_query_list[2])
    # Iterate over rest of items
    for x in range(3, len(dns_query_list)):
        # If another content exists and we find it, convert current list, then start building a new one
        if dns_query_list[x].find("content:") != -1:
            temp2 = convert_content_snort3(temp3, True)
            for item in temp2:
                temp.append(item)
            temp3 = []
            temp3.append(dns_query_list[x])
        # Else append additional option to current temp list
        else:
            temp3.append(dns_query_list[x])
    # If not more items convert current list
    temp2 = convert_content_snort3(temp3, True)
    for item in temp2:
        temp.append(item)
    # Update Alert field and replace http with udp
    converted_list[row_tracker][0] = re.sub('dns', 'udp', converted_list[row_tracker][0])
    return temp


# Helper Function takes Field Agent Keyword and unknown number of associated fields then converts them to Snort 3
def convert_user_agent_snort3(snort_list):
    # Count fields so you know how many to add to list
    field_count = len(snort_list)
    temp = []
    # Manually write modified header field
    temp.append("http_header: field user-agent")
    temp.append(";")
    temp.append(snort_list[0])
    # Add additional fields if they exist
    if field_count > 3:
        for x in range(3, field_count):
            temp.append(snort_list[x])
    return temp


# Helper Function takes HTTP_Header Keyword and unknown number of associated fields then converts them to Snort 3
def convert_http_header_snort3(header_list):
    # Count fields so you know how many to add to list
    field_count = len(header_list)
    temp = []
    # Switch HTTP_Header and CONTENT fields
    temp.append(header_list[2])
    temp.append(";")
    temp.append(header_list[0])
    # Add additional fields if they exist
    if field_count > 3:
        for x in range(3, field_count):
            temp.append(header_list[3])
    return temp


# Helper Function takes Content and unknown Key/value pairs and converts them to Snort 3 format
def convert_content_snort3(contentlist, hexswitch):
    for index, item in enumerate(contentlist):
        # Check Hex switch and if enabled convert the content field
        if index == 0 and hexswitch:
            b = contentlist[index].split(":")
            if b[1].find("!") != -1:
                contentlist[index] = b[0] + ":!" + convert_to_hex(b[1][1:])
            else:
                contentlist[index] = b[0] + ":" + convert_to_hex(b[1])
        # Skip the Content Field and leave it in place
        if index >= 1:
            # Search for alphanumerics (or NOT SYMBOLS) for content or key/value pairs
            if re.match(r"^[a-zA-Z0-9]", item[1:]):
                b = contentlist[index].split(":")
                if len(b) > 1:
                    contentlist[index] = b[0] + " " + b[1]
    contentlist[-1] = ";"
    return contentlist


# Helper function takes a Snort 3 content string and returns the hex version of the content string
def convert_to_hex (stringy):
    # Initialize variables
    answer = "\""
    temp5 = stringy[1:-1].split(".")
    field_count = len(temp5)
    # Iterate over each part of the domain and convert to hex
    for x in range(0, field_count):
        answer = answer + "|" + hex(len(temp5[x])) + "|" + temp5[x] + ""
    answer = answer + "\""
    return answer


# Helper Function takes SID and Generates new sequential ID's over 1000000 if they are BELOW, otherwise does nothing
def sid_changer_snort_3(sid_list):
    global sid_start_selector

    tmp = sid_list[0].split(":")
    if int(tmp[1]) <= sid_start_selector:
        sid_list[0] = "sid:" + str(sid_start_selector)
        sid_start_selector += 1
    return sid_list


# Helper function selects delimiters based on selected output format
def syntaxselector(state, output3):
    # Based on Output Selector, convert to proper fields for output syntax
    syntax = ""
    if output3 == "SNORT3":
        if not state:
            syntax = ","
        elif state:
            syntax = ";"
        else:
            syntax = "NONE"
    return syntax


# Helper function selects which keywords generate the Rule Index
def index_selector(item2, ingester2):
    # Search for keywords based in Ingest Selector to build index list
    # Modified to correctly build index based on sticky buffers for dns.query
    global keyword_tracker
    selector = False

    if ingester2 == "SURRICATA":
        for item in SurricataChunkKeywords:
            if item2.find(item) != -1:
                # Leading Keywords with possible content
                if keyword_tracker == "dns.query" and item == "content:":
                    selector = False
                else:
                    selector = True
                    keyword_tracker = item
    else:
        selector = False
    return selector


# Helper function the lookup table for conversions and calls the conversion functions
def keyword_selector(search_item, list_a, output3):
    # Based on Selector, convert to proper fields for output syntax
    if output3 == "SNORT3":
        # Check for leading keywords (fastest result with least waste)
        # if re.search("\\bhttp_user_agent\\b", list_a[2]) != None and re.search("\\bcontent\\b", search_item) != None:
        #     list_a = convert_user_agent_snort3(list_a)
        # elif re.search("\\bhttp_header\\b", list_a[2]) != None and re.search("\\bcontent\\b", search_item) != None:
        #     list_a = convert_http_header_snort3(list_a)
        if re.search("\\bsid\\b", search_item) != None:
            list_a = sid_changer_snort_3(list_a)
        elif re.search("\\bthreshold\\b", search_item) != None:
            list_a = convert_threshold_snort3(list_a)
        elif re.search("\\bdns.query\\b", search_item) != None:
            list_a = convert_dns_query_snort3(list_a)
        elif re.search("\\bcontent\\b", search_item) != None:
            # Check for trailing keywords:
            for item in list_a:
                if re.search("\\bhttp_user_agent\\b", item) != None:
                    list_a = convert_user_agent_snort3(list_a)
                    break
                elif re.search("\\bhttp_header\\b", item) != None:
                    list_a = convert_http_header_snort3(list_a)
                    break
                else:
                    list_a = convert_content_snort3(list_a, False)
    return list_a


# Function Creates Universal list for manipulation
def create_intermediate_list(rule_file):
    rules_list = []
    with open(rule_file, 'r', encoding='utf-8') as file1:
        # Read non-empty lines from file
        lines = [line for line in file1.readlines() if line.strip()]
        for line in lines:
            if line[0] != "#":
                # remove leading and trailing white space from each line (rule)
                line = line.strip()
                # Strip smart quotes only works on STRINGS so best to do it now...
                line = unidecode(line)
                # Separate each rule component into a list
                line = re.split(' \(|; ', line)
                # Remove Trailing bracket and semicolon
                line[-1] = line[-1][:-2]
                # Sanitize multiple errors
                line = sanitize_ingest_list(line)
                # compose rules into single list
                rules_list.append(line)
    return rules_list


# This function perform standardization and Sanitization of the ingestlist
def sanitize_ingest_list(list_a):
    # Fix Arrows
    list_a[0] = re.sub(r"(?<=\S)->", " ->", list_a[0])

    # Fix Miss-formatted semicolons
    for index, item in enumerate(list_a):
        if item.find(";") != -1:
            b = item.split(";")
            list_a[index] = b[0]
            list_a.insert(index + 1, b[1])

    # Fix skipped white space
    for index, item in enumerate(list_a):
        list_a[index] = list_a[index].strip()

    return list_a


# This function creates an index for each rule in the list given to it
def generate_rule_index(rule_list_2, ingester):
    index_list_2 = []
    # Search rule keywords and create index for "chunking"
    for index3, item3 in enumerate(rule_list_2):
        index_list_2.append([])
        for item2 in item3:
            state_check = index_selector(item2, ingester)
            if state_check:
                index_list_2[index3].append(True)
            else:
                index_list_2[index3].append(False)
    return index_list_2


# This function enumerates the INGEST rules and converts them to OUTPUT syntax
def convert_list(index_list_3, rules_list_3, output2):
    global converted_list
    global row_tracker

    temp_list = []

    # "For each rule" perform chunking and conversion
    for index, item in enumerate(index_list_3):
        row_tracker = index
        converted_list.append([])
        # First field of rule always behaves differently.... "alert....("
        temp_list.append(rules_list_3[index][0])
        temp_list.append(" (")
        for item3 in temp_list:
            converted_list[index].append(item3)
        temp_list = []
        # Add first non-alert field to the temporary list
        temp_list.append(rules_list_3[index][1])
        # Iterate over each of remaining items in the rule
        for index4, item4 in enumerate(index_list_3[index][2:], 2):
            # If index_list_3 is True, append syntax then dump current chunk and convert list, start again
            if index_list_3[index][index4]:
                temp_list.append(syntaxselector(index_list_3[index][index4], output2))
                # TODO: verify replacement function works as intended
                temp_list = keyword_selector(temp_list[0], temp_list, output2)
                # for index2, item2 in enumerate(temp_list):
                #     temp_list = keyword_selector(item2, temp_list, output2)
                #     logging.debug(temp_list)
                for item3 in temp_list:
                    converted_list[index].append(item3)
                temp_list = []
                temp_list.append(rules_list_3[index][index4])
            # Otherwise add to chunk
            else:
                temp_list.append(syntaxselector(index_list_3[index][index4], output2))
                temp_list.append(rules_list_3[index][index4])
        temp_list.append(syntaxselector(True, output2))
        temp_list.append(")")
        for item3 in temp_list:
            converted_list[index].append(item3)
        temp_list = []
    # return Full list of rules
    return converted_list


# This function takes the final converted rules and writes them to a file
def write_rules_to_file(lista, out_filename):
    with open(out_filename, 'w', encoding='utf-8') as file1:
        # Spacing Selector
        for index, item in enumerate(lista):
            for index2, item2 in enumerate(lista[index]):
                if index2 > 2:
                    if re.match(r"^[a-zA-Z0-9]", item2[1:]):
                        lista[index][index2] = " " + item2
        # For each "rule" (row) in List
        for item in lista:
            # ...Output all items in a joined line
            file1.write(''.join(item))
            # ...Then add a carriage return
            file1.write('\n')


def main(sid, ingest, output, infile, outfile):
    global sid_start_selector
    global keyword_tracker
    global converted_list
    global row_tracker

    row_tracker = 0
    sid_start_selector = sid
    keyword_tracker = "NONE"
    converted_list = []

    # Create Rule List from Ingest Set
    start_list = create_intermediate_list(infile)
    # Create Index for Key words (based in Ingest Selector)
    index_list = generate_rule_index(start_list, ingest)
    # Generate the Base Output List
    base_output_list = convert_list(index_list, start_list, output)
    # Use Emitter to generate final syntax rules
    write_rules_to_file(base_output_list, outfile)


SurricataChunkKeywords = ["byte_test", "pcre", "isdataat", "ssl", "alert", "msg:", "flow:", "content:", "reference:",
                          "classtype:", "metadata:", "sid", "rev", "threshold", "dns.query"]


if __name__ == '__main__':
    # TODO: Add McAfee, Forescout, Fortinet, Snort2
    # Initialize Argument Parser
    parser = argparse.ArgumentParser(description="Program Accepts Selected rule input and converts to selected output \
    rule type.")
    parser.add_argument("input_file", type=str, help="Full path to Source File")
    parser.add_argument("output_file", type=str, help="Full path for Output File")
    parser.add_argument("--source_rule_type", type=str, help="Source Rule OPTIONS: Surricata", default="SURRICATA")
    parser.add_argument("--output_rule_type", type=str, help="Output Rule OPTIONS: Snort3", default="SNORT3")
    parser.add_argument("--SID", type=int, help="Starting SID value for Snort rules", default="1000001")
    args = parser.parse_args()

    start = time.time()

    main(args.SID, args.source_rule_type, args.output_rule_type, args.input_file, args.output_file)

    end = time.time()
    print(f"Runtime of the program is {end - start}")
