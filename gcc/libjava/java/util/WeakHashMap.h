
// DO NOT EDIT THIS FILE - it is machine generated -*- c++ -*-

#ifndef __java_util_WeakHashMap__
#define __java_util_WeakHashMap__

#pragma interface

#include <java/util/AbstractMap.h>
#include <gcj/array.h>


class java::util::WeakHashMap : public ::java::util::AbstractMap
{

public:
  WeakHashMap();
  WeakHashMap(jint);
  WeakHashMap(jint, jfloat);
  WeakHashMap(::java::util::Map *);
private:
  jint hash(::java::lang::Object *);
public: // actually package-private
  virtual void cleanQueue();
private:
  void rehash();
  ::java::util::WeakHashMap$WeakBucket$WeakEntry * internalGet(::java::lang::Object *);
  void internalAdd(::java::lang::Object *, ::java::lang::Object *);
public: // actually package-private
  virtual void internalRemove(::java::util::WeakHashMap$WeakBucket *);
public:
  virtual jint size();
  virtual jboolean isEmpty();
  virtual jboolean containsKey(::java::lang::Object *);
  virtual ::java::lang::Object * get(::java::lang::Object *);
  virtual ::java::lang::Object * put(::java::lang::Object *, ::java::lang::Object *);
  virtual ::java::lang::Object * remove(::java::lang::Object *);
  virtual ::java::util::Set * entrySet();
  virtual void clear();
  virtual jboolean containsValue(::java::lang::Object *);
  virtual ::java::util::Set * keySet();
  virtual void putAll(::java::util::Map *);
  virtual ::java::util::Collection * values();
private:
  static const jint DEFAULT_CAPACITY = 11;
  static jfloat DEFAULT_LOAD_FACTOR;
public: // actually package-private
  static ::java::lang::Object * NULL_KEY;
private:
  ::java::lang::ref::ReferenceQueue * __attribute__((aligned(__alignof__( ::java::util::AbstractMap)))) queue;
public: // actually package-private
  jint size__;
private:
  jfloat loadFactor;
  jint threshold;
public: // actually package-private
  jint modCount;
private:
  ::java::util::WeakHashMap$WeakEntrySet * theEntrySet;
public: // actually package-private
  JArray< ::java::util::WeakHashMap$WeakBucket * > * buckets;
public:
  static ::java::lang::Class class$;
};

#endif // __java_util_WeakHashMap__