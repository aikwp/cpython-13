/*
 * _blake3 — BLAKE3 hash module for CPython (intended for hashlib integration)
 *
 * Uses the official BLAKE3 C reference implementation vendored in impl/
 *
 * Supported constructor arguments:
 *     data (optional bytes-like)        → immediate update
 *     key (optional bytes, len=32)      → keyed mode
 *     context (optional bytes-like)     → derive-key mode (domain separation)
 *     max_threads (int, default=-1)     → accepted but ignored (C impl is single-threaded)
 *
 * Methods:
 *     update(data)
 *     digest(*, length=32) → bytes
 *     hexdigest(*, length=64) → str
 *     copy() → new BLAKE3 object
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "impl/blake3.h"

/* ----------------------------------------------------------------------------
   Object definition
   ---------------------------------------------------------------------------- */

typedef struct {
    PyObject_HEAD
    blake3_hasher hasher;
} BLAKE3Object;

static PyTypeObject BLAKE3_Type;

/* Forward declarations */
static PyObject *blake3_new(PyTypeObject *, PyObject *, PyObject *);
static int       blake3_init(BLAKE3Object *, PyObject *, PyObject *);
static void      blake3_dealloc(BLAKE3Object *);
static int       blake3_traverse(BLAKE3Object *, visitproc, void *);
static int       blake3_clear(BLAKE3Object *);
static PyObject *blake3_update(BLAKE3Object *, PyObject *);
static PyObject *blake3_digest(BLAKE3Object *, PyObject *, PyObject *);
static PyObject *blake3_hexdigest(BLAKE3Object *, PyObject *, PyObject *);
static PyObject *blake3_copy(BLAKE3Object *, PyObject *);

/* ----------------------------------------------------------------------------
   Construction
   ---------------------------------------------------------------------------- */

static PyObject *
blake3_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    BLAKE3Object *self = (BLAKE3Object *)type->tp_alloc(type, 0);
    if (self != NULL) {
        blake3_hasher_init(&self->hasher);
    }
    return (PyObject *)self;
}

static int
blake3_init(BLAKE3Object *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"data", "key", "context", "max_threads", NULL};

    Py_buffer data = {0}, key = {0}, context = {0};
    int max_threads = -1;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|y*y*y*i", kwlist,
                                     &data, &key, &context, &max_threads)) {
        return -1;
    }

    /* key and context are mutually exclusive */
    if (key.obj != NULL && context.obj != NULL) {
        PyErr_SetString(PyExc_TypeError,
                        "cannot specify both 'key' and 'context'");
        goto fail;
    }

    if (context.obj != NULL) {
        if (context.len == 0) {
            PyErr_SetString(PyExc_ValueError, "context must not be empty");
            goto fail;
        }
        blake3_hasher_init_derive_key_raw(&self->hasher,
                                          context.buf,
                                          (size_t)context.len);
    }
    else if (key.obj != NULL) {
        if (key.len != BLAKE3_KEY_LEN) {
            PyErr_SetString(PyExc_ValueError,
                            "key must be exactly 32 bytes long");
            goto fail;
        }
        blake3_hasher_init_keyed(&self->hasher,
                                 (const uint8_t *)key.buf);
    }
    else {
        blake3_hasher_init(&self->hasher);
    }

    if (data.obj != NULL && data.len > 0) {
        blake3_hasher_update(&self->hasher, data.buf, (size_t)data.len);
    }

    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    PyBuffer_Release(&context);
    return 0;

fail:
    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    PyBuffer_Release(&context);
    return -1;
}

/* ----------------------------------------------------------------------------
   GC support
   ---------------------------------------------------------------------------- */

static void
blake3_dealloc(BLAKE3Object *self)
{
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static int
blake3_traverse(BLAKE3Object *self, visitproc visit, void *arg)
{
    return 0;
}

static int
blake3_clear(BLAKE3Object *self)
{
    return 0;
}

/* ----------------------------------------------------------------------------
   Methods
   ---------------------------------------------------------------------------- */

PyDoc_STRVAR(update_doc,
"update($self, data, /)\n\
--\n\
Update the hasher with more data.");

static PyObject *
blake3_update(BLAKE3Object *self, PyObject *arg)
{
    Py_buffer view = {0};

    if (!PyArg_Parse(arg, "y*:update", &view))
        return NULL;

    blake3_hasher_update(&self->hasher, view.buf, (size_t)view.len);
    PyBuffer_Release(&view);

    Py_RETURN_NONE;
}

PyDoc_STRVAR(digest_doc,
"digest($self, /, *, length=32)\n\
--\n\
Return the digest of the data (extendable output mode).");

static PyObject *
blake3_digest(BLAKE3Object *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"length", NULL};
    Py_ssize_t length = BLAKE3_OUT_LEN;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|n:digest", kwlist, &length))
        return NULL;

    if (length <= 0) {
        PyErr_SetString(PyExc_ValueError, "length must be positive");
        return NULL;
    }

    PyObject *result = PyBytes_FromStringAndSize(NULL, length);
    if (result == NULL)
        return NULL;

    blake3_hasher_finalize_seek(&self->hasher, 0,
                                (uint8_t *)PyBytes_AS_STRING(result),
                                (size_t)length);

    return result;
}

PyDoc_STRVAR(hexdigest_doc,
"hexdigest($self, /, *, length=64)\n\
--\n\
Return the hex-encoded digest (extendable output mode).");

static PyObject *
blake3_hexdigest(BLAKE3Object *self, PyObject *args, PyObject *kwlist)
{
    PyObject *bytes = blake3_digest(self, args, kwlist);
    if (bytes == NULL)
        return NULL;

    Py_ssize_t len = PyBytes_GET_SIZE(bytes);
    PyObject *hex = PyUnicode_FromStringAndSize(NULL, len * 2);
    if (hex == NULL) {
        Py_DECREF(bytes);
        return NULL;
    }

    char *dst = PyUnicode_AS_UNICODE(hex);
    const unsigned char *src = (const unsigned char *)PyBytes_AS_STRING(bytes);

    for (Py_ssize_t i = 0; i < len; i++) {
        sprintf(dst + i * 2, "%02x", src[i]);
    }

    Py_DECREF(bytes);
    return hex;
}

PyDoc_STRVAR(copy_doc,
"copy($self, /)\n\
--\n\
Return a copy of the current hasher state.");

static PyObject *
blake3_copy(BLAKE3Object *self, PyObject *Py_UNUSED(ignored))
{
    BLAKE3Object *copy = PyObject_GC_New(BLAKE3Object, Py_TYPE(self));
    if (copy == NULL)
        return NULL;

    copy->hasher = self->hasher;  /* structure copy is safe */

    PyObject_GC_Track(copy);
    return (PyObject *)copy;
}

/* ----------------------------------------------------------------------------
   Method table
   ---------------------------------------------------------------------------- */

static PyMethodDef blake3_methods[] = {
    {"update",    (PyCFunction)blake3_update,    METH_O,      update_doc},
    {"digest",    (PyCFunction)blake3_digest,    METH_VARARGS|METH_KEYWORDS, digest_doc},
    {"hexdigest", (PyCFunction)blake3_hexdigest, METH_VARARGS|METH_KEYWORDS, hexdigest_doc},
    {"copy",      (PyCFunction)blake3_copy,      METH_NOARGS, copy_doc},
    {NULL}
};

/* ----------------------------------------------------------------------------
   Type definition
   ---------------------------------------------------------------------------- */

static PyType_Spec BLAKE3_spec = {
    .name      = "_blake3.BLAKE3",
    .basicsize = sizeof(BLAKE3Object),
    .flags     = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .slots     = (PyType_Slot[]) {
        {Py_tp_new,      blake3_new},
        {Py_tp_init,     blake3_init},
        {Py_tp_dealloc,  blake3_dealloc},
        {Py_tp_traverse, blake3_traverse},
        {Py_tp_clear,    blake3_clear},
        {Py_tp_methods,  blake3_methods},
        {Py_tp_doc,      "BLAKE3 hash object"},
        {0, NULL}
    }
};

/* ----------------------------------------------------------------------------
   Module definition
   ---------------------------------------------------------------------------- */

PyDoc_STRVAR(module_doc,
"_blake3 — BLAKE3 hash function (CPython native implementation)\n"
);

static struct PyModuleDef _blake3_module = {
    PyModuleDef_HEAD_INIT,
    ._m_name   = "_blake3",
    .m_doc     = module_doc,
    .m_size    = 0,
    .m_slots   = (PyModuleDef_Slot[]) {
        {Py_mod_gil, Py_MOD_GIL_NOT_USED},  /* 3.13+ free-threaded compatibility */
        {0, NULL}
    }
};

PyMODINIT_FUNC
PyInit__blake3(void)
{
    PyObject *m = PyModuleDef_Init(&_blake3_module);
    if (m == NULL)
        return NULL;

    PyTypeObject *type = (PyTypeObject *)PyType_FromModuleAndSpec(
        m, &BLAKE3_spec, NULL);
    if (type == NULL)
        goto error;

    if (PyModule_AddType(m, type) < 0) {
        Py_DECREF(type);
        goto error;
    }

#define ADD_CONSTANT(name, value) \
    if (PyModule_AddIntConstant(m, name, value) < 0) goto error

    ADD_CONSTANT("KEY_LENGTH",    BLAKE3_KEY_LEN);
    ADD_CONSTANT("DIGEST_LENGTH", BLAKE3_OUT_LEN);
    ADD_CONSTANT("BLOCK_LENGTH",  BLAKE3_BLOCK_LEN);
    ADD_CONSTANT("CHUNK_LENGTH",  BLAKE3_CHUNK_LEN);
    ADD_CONSTANT("MAX_DEPTH",     BLAKE3_MAX_DEPTH);
    ADD_CONSTANT("AUTO",          -1);

#undef ADD_CONSTANT

    PyObject *mt = PyBool_FromLong(0);
    if (PyModule_AddObjectRef(m, "supports_multithreading", mt) < 0) {
        Py_DECREF(mt);
        goto error;
    }
    Py_DECREF(mt);

    return m;

error:
    Py_XDECREF(type);
    Py_XDECREF(m);
    return NULL;
}
