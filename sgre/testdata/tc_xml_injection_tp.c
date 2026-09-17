#include <libxml/parser.h>
#include <libxml/xpath.h>

void test_xml_injection_tp_xpath(char *user_input, xmlXPathContextPtr ctx) {
    xmlXPathEvalExpression(ctx, user_input);
}

void test_xml_injection_tp_parse(char *user_input) {
    xmlSAXParseDoc(NULL, user_input, 0);
}