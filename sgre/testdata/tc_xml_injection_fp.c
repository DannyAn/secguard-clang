#include <libxml/parser.h>
#include <libxml/xpath.h>

void test_xml_injection_fp_const_xpath(xmlXPathContextPtr ctx) {
    xmlXPathEvalExpression(ctx, "//node[@id='1']");
}

void test_xml_injection_fp_precompiled(xmlXPathContextPtr ctx) {
    xmlXPathCompExprPtr compiled = xmlXPathCompileExpr("//node[@id='1']");
    xmlXPathCompiledEval(compiled, ctx);
}

void test_xml_injection_fp_const_parse(void) {
    xmlSAXParseDoc(NULL, "<root><node/></root>", 0);
}