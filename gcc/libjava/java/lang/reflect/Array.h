
// DO NOT EDIT THIS FILE - it is machine generated -*- c++ -*-

#ifndef __java_lang_reflect_Array__
#define __java_lang_reflect_Array__

#pragma interface

#include <java/lang/Object.h>
#include <gcj/array.h>


class java::lang::reflect::Array : public ::java::lang::Object
{

  Array();
public:
  static ::java::lang::Object * newInstance(::java::lang::Class *, jint);
  static ::java::lang::Object * newInstance(::java::lang::Class *, JArray< jint > *);
  static jint getLength(::java::lang::Object *);
  static ::java::lang::Object * get(::java::lang::Object *, jint);
  static jboolean getBoolean(::java::lang::Object *, jint);
  static jbyte getByte(::java::lang::Object *, jint);
  static jchar getChar(::java::lang::Object *, jint);
  static jshort getShort(::java::lang::Object *, jint);
  static jint getInt(::java::lang::Object *, jint);
  static jlong getLong(::java::lang::Object *, jint);
  static jfloat getFloat(::java::lang::Object *, jint);
  static jdouble getDouble(::java::lang::Object *, jint);
private:
  static ::java::lang::Class * getElementType(::java::lang::Object *, jint);
  static void set(::java::lang::Object *, jint, ::java::lang::Object *, ::java::lang::Class *);
public:
  static void set(::java::lang::Object *, jint, ::java::lang::Object *);
  static void setBoolean(::java::lang::Object *, jint, jboolean);
  static void setByte(::java::lang::Object *, jint, jbyte);
  static void setChar(::java::lang::Object *, jint, jchar);
  static void setShort(::java::lang::Object *, jint, jshort);
  static void setInt(::java::lang::Object *, jint, jint);
  static void setLong(::java::lang::Object *, jint, jlong);
  static void setFloat(::java::lang::Object *, jint, jfloat);
  static void setDouble(::java::lang::Object *, jint, jdouble);
  static ::java::lang::Class class$;
};

#endif // __java_lang_reflect_Array__
