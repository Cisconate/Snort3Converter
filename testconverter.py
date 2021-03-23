import snort3convert

def testfunction ():
    snort3convert.main(1000000, "SURICATA", "SNORT3", "testsuricatainputrules.txt", "testoutput.txt")
    with open("testsnort3outputrules.txt", 'r', encoding='utf-8') as file1:
        data1 = file1.readlines()
    with open("testoutput.txt", 'r', encoding='utf-8') as file2:
        data2 = file2.readlines()

    assert data1 == data2
