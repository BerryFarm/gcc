
// DO NOT EDIT THIS FILE - it is machine generated -*- c++ -*-

#ifndef __org_w3c_dom_css_DOMImplementationCSS__
#define __org_w3c_dom_css_DOMImplementationCSS__

#pragma interface

#include <java/lang/Object.h>
extern "Java"
{
  namespace org
  {
    namespace w3c
    {
      namespace dom
      {
          class Document;
          class DocumentType;
        namespace css
        {
            class CSSStyleSheet;
            class DOMImplementationCSS;
        }
      }
    }
  }
}

class org::w3c::dom::css::DOMImplementationCSS : public ::java::lang::Object
{

public:
  virtual ::org::w3c::dom::css::CSSStyleSheet * createCSSStyleSheet(::java::lang::String *, ::java::lang::String *) = 0;
  virtual jboolean hasFeature(::java::lang::String *, ::java::lang::String *) = 0;
  virtual ::org::w3c::dom::DocumentType * createDocumentType(::java::lang::String *, ::java::lang::String *, ::java::lang::String *) = 0;
  virtual ::org::w3c::dom::Document * createDocument(::java::lang::String *, ::java::lang::String *, ::org::w3c::dom::DocumentType *) = 0;
  virtual ::java::lang::Object * getFeature(::java::lang::String *, ::java::lang::String *) = 0;
  static ::java::lang::Class class$;
} __attribute__ ((java_interface));

#endif // __org_w3c_dom_css_DOMImplementationCSS__
