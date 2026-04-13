require "xml"
# NONET hint present — should not fire
XML.parse(trusted_xml, XML::ParserOptions::NONET)
