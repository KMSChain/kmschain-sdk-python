#include "Python.h"
#include <stdio.h>
#include "proxy_c.h"
#include <string>

void pycapsule_destructor(PyObject * obj)
{
    const char* nm = PyCapsule_GetName(obj);
    void* obj_Ptr = PyCapsule_GetPointer(obj, nm);
    std::string name = nm;
 
    if (name == "cm")
    {
        proxylib_clear(obj_Ptr);
    }
    else if (name == "sk")
    {
        proxylib_private_key_free(obj_Ptr);
    }
    else if(name == "pk")
    {
        proxylib_public_key_free(obj_Ptr);
    }
    else if(name == "rk")
    {
        proxylib_re_encryption_key_free(obj_Ptr);
    }
    else if(name == "capsule")
    {
        proxylib_capsule_free(obj_Ptr);
    }
    else{
    }
}

static PyObject* proxylib_init_wrapper(PyObject *self, PyObject *args) 
{
    proxylib_init();
    Py_RETURN_NONE;    
}


static PyObject* proxylib_new_wrapper(PyObject *self, PyObject *args) 
{
    void* cm_obj = proxylib_new();
    PyObject* cm_Ptr = PyCapsule_New(cm_obj, "cm", &pycapsule_destructor);
    PyCapsule_SetName(cm_Ptr, "cm");
    return cm_Ptr;
}

static PyObject* proxylib_generate_private_key_wrapper(PyObject *self, PyObject *args) 
{
    PyObject* cm_obj;

    if (! PyArg_UnpackTuple( args, "cm_obj",0,1, &cm_obj))
        return NULL;

    void* cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm");
    void* sk_Ptr = proxylib_generate_private_key(cm_Ptr);
    PyObject* sk = PyCapsule_New(sk_Ptr, "sk", &pycapsule_destructor); 
    PyCapsule_SetName(sk, "sk");
    return sk;
}

static PyObject* proxylib_get_public_key_wrapper(PyObject *self, PyObject * args)
{
    PyObject* sk_Ptr;

    if (! PyArg_UnpackTuple( args, "sk_obj",0,1, &sk_Ptr))
        return NULL;

    void* pk_Ptr = proxylib_get_public_key(PyCapsule_GetPointer(sk_Ptr, "sk"));
    PyObject* pk = PyCapsule_New(pk_Ptr, "pk", &pycapsule_destructor);
    PyCapsule_SetName(pk, "pk");
    return pk;
}

static PyObject* proxylib_private_key_to_bytes_wrapper(PyObject *self, PyObject * args)
{
    PyObject* sk_Ptr;
    
    if (! PyArg_UnpackTuple( args, "to_bytes",0,1, &sk_Ptr))
        return NULL;

    char *buffer;
    int length; 

    proxylib_private_key_to_bytes(PyCapsule_GetPointer(sk_Ptr, "sk"), &buffer, &length);
    return PyByteArray_FromStringAndSize(buffer, length);
}

static PyObject* proxylib_public_key_to_bytes_wrapper(PyObject *self, PyObject * args)
{
    PyObject* pk_Ptr;

    
    if (! PyArg_UnpackTuple( args, "to_bytes",0,1, &pk_Ptr))
        return NULL;

    char *buffer;
    int length; 

    proxylib_public_key_to_bytes(PyCapsule_GetPointer(pk_Ptr, "pk"), &buffer, &length);
    return PyByteArray_FromStringAndSize(buffer, length);
}

static PyObject* proxylib_private_key_from_bytes_wrapper(PyObject *self, PyObject * args)
{
    PyObject* cm_obj;
    PyObject* data;
    
    if (! PyArg_UnpackTuple( args, "from_bytes",2,2, &cm_obj, &data))
        return NULL;

    const char* buffer = PyBytes_AsString(data);
    void* cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm"); 
    void* sk_obj = proxylib_private_key_from_bytes(cm_Ptr, buffer, strlen(buffer));
    PyObject* sk_Ptr = PyCapsule_New(sk_obj, "sk", &pycapsule_destructor);
    PyCapsule_SetName(sk_Ptr, "sk");
    return sk_Ptr;
}

static PyObject* proxylib_public_key_from_bytes_wrapper(PyObject *self, PyObject * args)
{
    PyObject* cm_obj;
    PyObject* data;
    
    if (! PyArg_UnpackTuple( args, "from_bytes",2,2, &cm_obj, &data))
        return NULL;

    char* buffer = PyBytes_AsString(data);
    void* cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm"); 
    void* pk_obj = proxylib_public_key_from_bytes(cm_Ptr, buffer, strlen(buffer));
    PyObject* pk_Ptr = PyCapsule_New(pk_obj, "pk", &pycapsule_destructor);
    PyCapsule_SetName(pk_Ptr, "pk");
    return pk_Ptr;
}

static PyObject* proxylib_encapsulate_wrapper(PyObject *self, PyObject * args)
{
    PyObject* cm_obj;
    PyObject* pk_obj;
    
    if (! PyArg_UnpackTuple( args, "_obj", 2, 2, &cm_obj, &pk_obj))
        return NULL;
 
    void* cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm");
    void* pk_Ptr = PyCapsule_GetPointer(pk_obj, "pk");

    char *buffer;
    int length; 
    void* capsule_obj = proxylib_encapsulate(cm_Ptr, pk_Ptr, &buffer, &length);
    PyObject* capsule_Ptr = PyCapsule_New(capsule_obj, "capsule", &pycapsule_destructor);
    PyCapsule_SetName(capsule_Ptr, "capsule");
    PyObject* symmetric_key = PyByteArray_FromStringAndSize(buffer, length);
 
    PyObject* tuple_Ptr = PyTuple_Pack(2, capsule_Ptr, symmetric_key);
 
    return tuple_Ptr; 
}

static PyObject* proxylib_decapsulate_wrapper(PyObject *self, PyObject * args)
{
    PyObject* cm_obj;
    PyObject* sk_obj;
    PyObject* capsule_obj;
    
    if (! PyArg_UnpackTuple( args, "_obj",3,3, &cm_obj, &sk_obj, &capsule_obj))
        return NULL;

    char *buffer;
    int length; 

    void* cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm");
    void* sk_Ptr = PyCapsule_GetPointer(sk_obj, "sk");
    void* capsule_Ptr = PyCapsule_GetPointer(capsule_obj, "capsule");
    proxylib_decapsulate(cm_Ptr, capsule_Ptr, sk_Ptr, &buffer, &length);
    PyObject* symmetric_key = PyByteArray_FromStringAndSize(buffer, length);
   
    return symmetric_key; 
}

static PyObject* proxylib_capsule_to_bytes_wrapper(PyObject *self, PyObject * args)
{
    PyObject* capsule_obj;
    
    if (! PyArg_UnpackTuple( args, "to_bytes",0,1, &capsule_obj))
        return NULL;

    char *buffer;
    int length; 

    proxylib_capsule_to_bytes(PyCapsule_GetPointer(capsule_obj, "capsule"), &buffer, &length);
    return PyByteArray_FromStringAndSize(buffer, length);
}

static PyObject* proxylib_capsule_from_bytes_wrapper(PyObject *self, PyObject * args)
{
    PyObject* cm_obj;
    PyObject* data;
    
    if (! PyArg_UnpackTuple( args, "from_bytes",2,2, &cm_obj, &data))
        return NULL;

    char* buffer = PyBytes_AsString(data);
    void* cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm"); 
    void* capsule_obj = proxylib_capsule_from_bytes(cm_Ptr, buffer, strlen(buffer));
    PyObject* capsule_Ptr = PyCapsule_New(capsule_obj, "capsule", &pycapsule_destructor);
    PyCapsule_SetName(capsule_Ptr, "capsule");
    return capsule_Ptr;
}

static PyObject* proxylib_get_re_encryption_key_wrapper(PyObject *self, PyObject * args)
{
    PyObject* cm_obj;
    PyObject* sk_obj;
    PyObject* pk_obj;
    
    if (! PyArg_UnpackTuple( args, "from_bytes",3,3, &sk_obj, &pk_obj, &cm_obj))
        return NULL;

    void * cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm");
    void * sk_Ptr = PyCapsule_GetPointer(sk_obj, "sk");
    void * pk_Ptr = PyCapsule_GetPointer(pk_obj, "pk");

    void* rk_obj = proxylib_get_re_encryption_key(cm_Ptr, sk_Ptr, pk_Ptr);
    PyObject* rk_Ptr = PyCapsule_New(rk_obj, "rk", &pycapsule_destructor);
    PyCapsule_SetName(rk_Ptr, "rk");
    return rk_Ptr;  
}

static PyObject* proxylib_get_re_encryption_from_bytes_wrapper(PyObject *self, PyObject * args)
{
    PyObject* cm_obj;
    PyObject* data;
    
    if (! PyArg_UnpackTuple( args, "from_bytes",2,2, &cm_obj, &data))
        return NULL;

    char* buffer = PyBytes_AsString(data);
    void* cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm"); 
    void* rk_obj = proxylib_get_re_encryption_from_bytes(cm_Ptr, buffer, strlen(buffer));
    PyObject* rk_Ptr = PyCapsule_New(rk_obj, "rk", &pycapsule_destructor);
    PyCapsule_SetName(rk_Ptr, "rk");
    return rk_Ptr;
}

static PyObject* proxylib_re_encryption_to_bytes_wrapper(PyObject *self, PyObject * args)
{
    PyObject* rk_Ptr;
    
    if (! PyArg_UnpackTuple( args, "to_bytes",1,1, &rk_Ptr))
        return NULL;

    char *buffer;
    int length; 

    proxylib_re_encryption_to_bytes(PyCapsule_GetPointer(rk_Ptr, "rk"), &buffer, &length);
    return PyByteArray_FromStringAndSize(buffer, length);
}

static PyObject* proxylib_get_re_encryption_capsule_wrapper(PyObject *self, PyObject *args)
{
    PyObject* cm_obj;
    PyObject* capsule_obj;
    PyObject* rk_obj;

    if (! PyArg_UnpackTuple( args, "cm_obj", 3, 3, &cm_obj, &capsule_obj, &rk_obj))
        return NULL;

    void* cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm"); 
    void* rk_Ptr = PyCapsule_GetPointer(rk_obj, "rk"); 
    void* capsule_Ptr = PyCapsule_GetPointer(capsule_obj, "capsule");
    void* recapsule_Ptr = proxylib_get_re_encryption_capsule(cm_Ptr, capsule_Ptr, rk_Ptr);
    PyObject* recapsule = PyCapsule_New(recapsule_Ptr, "capsule", &pycapsule_destructor);
    PyCapsule_SetName(recapsule, "capsule");
    return recapsule; 
}

static PyMethodDef proxylib_methods[] = {
    {
        "proxylib_init", proxylib_init_wrapper, METH_NOARGS,
    },
    {
        "proxylib_new", proxylib_new_wrapper, METH_NOARGS,
    },
    {
        "proxylib_generate_private_key", proxylib_generate_private_key_wrapper, METH_VARARGS,
    },
    {
        "proxylib_get_public_key", proxylib_get_public_key_wrapper, METH_VARARGS,
    },
    {
        "proxylib_private_key_to_bytes", proxylib_private_key_to_bytes_wrapper, METH_VARARGS,
    },
    {
        "proxylib_public_key_to_bytes", proxylib_public_key_to_bytes_wrapper, METH_VARARGS,
    },
    {
        "proxylib_private_key_from_bytes", proxylib_private_key_from_bytes_wrapper, METH_VARARGS,
    },
    {
        "proxylib_public_key_from_bytes", proxylib_public_key_from_bytes_wrapper, METH_VARARGS,
    },
    {
        "proxylib_encapsulate", proxylib_encapsulate_wrapper, METH_VARARGS,
    },
    {
        "proxylib_decapsulate", proxylib_decapsulate_wrapper, METH_VARARGS,
    },
    {
        "proxylib_capsule_to_bytes", proxylib_capsule_to_bytes_wrapper, METH_VARARGS,
    },
    {
        "proxylib_capsule_from_bytes", proxylib_capsule_from_bytes_wrapper, METH_VARARGS,
    },
    {
        "proxylib_get_re_encryption_key", proxylib_get_re_encryption_key_wrapper, METH_VARARGS,
    }, 
    {
        "proxylib_get_re_encryption_from_bytes", proxylib_get_re_encryption_from_bytes_wrapper, METH_VARARGS,
    }, 
    {
        "proxylib_re_encryption_to_bytes", proxylib_re_encryption_to_bytes_wrapper, METH_VARARGS,
    }, 
    {
        "proxylib_get_re_encryption_capsule", proxylib_get_re_encryption_capsule_wrapper, METH_VARARGS,
    }, 
    {NULL, NULL, 0, NULL}
};

// Module definition
// The arguments of this structure tell Python what to call your extension,
// what it's methods are and where to look for it's method definitions
static struct PyModuleDef proxylib_definition = {
    PyModuleDef_HEAD_INIT,
    "proxylib",
    "A Python module extension for C++ lib",
    -1,
    proxylib_methods
};

PyMODINIT_FUNC PyInit_proxylib(void) {
    Py_Initialize();
    return PyModule_Create(&proxylib_definition);
}

