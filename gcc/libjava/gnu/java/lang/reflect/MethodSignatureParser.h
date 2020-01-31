
// DO NOT EDIT THIS FILE - it is machine generated -*- c++ -*-

#ifndef __gnu_java_lang_reflect_MethodSignatureParser__
#define __gnu_java_lang_reflect_MethodSignatureParser__

#pragma interface

#include <gnu/java/lang/reflect/GenericSignatureParser.h>
#include <gcj/array.h>

extern "Java"
{
  namespace gnu
  {
    namespace java
    {
      namespace lang
      {
        namespace reflect
        {
            class MethodSignatureParser;
        }
      }
    }
  }
}

class gnu::java::lang::reflect::MethodSignatureParser : public ::gnu::java::lang::reflect::GenericSignatureParser
{

public:
  MethodSignatureParser(::java::lang::reflect::Method *, ::java::lang::String *);
  MethodSignatureParser(::java::lang::reflect::Constructor *, ::java::lang::String *);
private:
  MethodSignatureParser(::java::lang::reflect::GenericDeclaration *, ::java::lang::ClassLoader *, ::java::lang::String *);
public:
  virtual JArray< ::java::lang::reflect::TypeVariable * > * getTypeParameters();
  virtual JArray< ::java::lang::reflect::Type * > * getGenericParameterTypes();
  virtual ::java::lang::reflect::Type * getGenericReturnType();
  virtual JArray< ::java::lang::reflect::Type * > * getGenericExceptionTypes();
private:
  ::java::lang::reflect::Type * readTypeSignature();
  JArray< ::java::lang::reflect::TypeVariable * > * __attribute__((aligned(__alignof__( ::gnu::java::lang::reflect::GenericSignatureParser)))) typeParameters;
  JArray< ::java::lang::reflect::Type * > * argTypes;
  ::java::lang::reflect::Type * retType;
  JArray< ::java::lang::reflect::Type * > * throwsSigs;
public:
  static ::java::lang::Class class$;
};

#endif // __gnu_java_lang_reflect_MethodSignatureParser__
