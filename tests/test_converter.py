from snort3_conv_tools import snort3convert
import os

def test_function (tmp_path):
    snort3convert.surricata_to_snort3(1000000, "SURICATA", "SNORT3", "../tests/data_files/testsuricatainputrules.txt", tmp_path/"testoutput.txt")
    with open("../tests/data_files/testsnort3outputrules.txt", 'r', encoding='utf-8') as file1:
        data1 = file1.readlines()
    with open(tmp_path/"testoutput.txt", 'r', encoding='utf-8') as file2:
        data2 = file2.readlines()

    assert data1 == data2
