/* Modules/_blake3module.c
 *
 * Native BLAKE3 implementation for CPython (vendored C reference)
 */

#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include "blake3.h"

#define BLAKE3_DEFAULT_DIGEST_SIZE 32

typedef struct {
    PyObject_HEAD
    blake3_hasher hasher;
    Py_ssize_t digest_size;
} Blake3Object;

static PyTypeObject Blake3_Type;

static PyObject *
blake3_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"data", "digest_size", "key", "usedforsecurity", NULL};
    PyObject *data = NULL, *key = NULL, *usedforsecurity = NULL;
    Py_ssize_t digest_size = BLAKE3_DEFAULT_DIGEST_SIZE;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|On$Op:blake3", kwlist,
                                     &data, &digest_size, &key, &usedforsecurity))
        return NULL;

    /* usedforsecurity is ignored (BLAKE3 is not FIPS); present for hashlib compatibility */
    if (usedforsecurity && PyObject_IsTrue(usedforsecurity)) {
        /* No-op; could raise in strict FIPS mode if desired */
    }

    if (digest_size < 1 || digest_size > 65536) {
        PyErr_SetString(PyExc_ValueError, "digest_size must be 1–65536");
        return NULL;
    }

    Blake3Object *self = (Blake3Object *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    self->digest_size = digest_size;

    if (key != NULL && key != Py_None) {
        Py_buffer kbuf;
        if (PyObject_GetBuffer(key, &kbuf, PyBUF_SIMPLE) < 0 ||
            kbuf.len != BLAKE3_KEY_LEN) {
            PyErr_Format(PyExc_ValueError, "key must be exactly %d bytes", BLAKE3_KEY_LEN);
            if (kbuf.obj) PyBuffer_Release(&kbuf);
            Py_DECREF(self);
            return NULL;
        }
        blake3_hasher_init_keyed(&self->hasher, (const uint8_t *)kbuf.buf);
        PyBuffer_Release(&kbuf);
    } else {
        blake3_hasher_init(&self->hasher);
    }

    if (data != NULL && data != Py_None) {
        Py_buffer vbuf;
        if (PyObject_GetBuffer(data, &vbuf, PyBUF_SIMPLE) == 0) {
            blake3_hasher_update(&self->hasher, vbuf.buf, (size_t)vbuf.len);
            PyBuffer_Release(&vbuf);
        } else {
            Py_DECREF(self);
            return NULL;
        }
    }

    return (PyObject *)self;
}

static void
Blake3_dealloc(Blake3Object *self)
{
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
Blake3_update(Blake3Object *self, PyObject *arg)
{
    Py_buffer view;
    if (!PyArg_Parse(arg, "y*:update", &view))
        return NULL;
    blake3_hasher_update(&self->hasher, view.buf, (size_t)view.len);
    PyBuffer_Release(&view);
    Py_RETURN_NONE;
}

static PyObject *
Blake3_digest(Blake3Object *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"length", NULL};
    Py_ssize_t length = self->digest_size;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|n:digest", kwlist, &length))
        return NULL;
    if (length <= 0) {
        PyErr_SetString(PyExc_ValueError, "length must be positive");
        return NULL;
    }
    PyObject *result = PyBytes_FromStringAndSize(NULL, length);
    if (!result)
        return NULL;
    blake3_hasher_finalize_seek(&self->hasher, 0,
                                (uint8_t *)PyBytes_AS_STRING(result),
                                (size_t)length);
    return result;
}

static PyObject *
Blake3_hexdigest(Blake3Object *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"length", NULL};
    Py_ssize_t length = self->digest_size;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|n:hexdigest", kwlist, &length)) {
        return NULL;
    }

    if (length <= 0) {
        PyErr_SetString(PyExc_ValueError, "length must be positive");
        return NULL;
    }

    PyObject *digest = Blake3_digest(self, args, kwds);
    if (digest == NULL) {
        return NULL;
    }

    Py_ssize_t digest_len = PyBytes_GET_SIZE(digest);
    const unsigned char *bytes = (const unsigned char *)PyBytes_AS_STRING(digest);

    /* We'll build the hex string incrementally */
    PyObject *hex = PyUnicode_New(digest_len * 2, 127);  /* ASCII range */
    if (hex == NULL) {
        Py_DECREF(digest);
        return NULL;
    }

    Py_ssize_t pos = 0;
    for (Py_ssize_t i = 0; i < digest_len; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", bytes[i]);

        /* Append two characters */
        if (PyUnicode_WriteChar(hex, pos++, (Py_UCS4)buf[0]) < 0 ||
            PyUnicode_WriteChar(hex, pos++, (Py_UCS4)buf[1]) < 0) {
            Py_DECREF(hex);
            Py_DECREF(digest);
            return NULL;
        }
    }

    Py_DECREF(digest);
    return hex;
}

static PyObject *
Blake3_copy(Blake3Object *self, PyObject *Py_UNUSED(ignored))
{
    Blake3Object *copy = (Blake3Object *)Blake3_Type.tp_alloc(&Blake3_Type, 0);
    if (!copy)
        return NULL;
    copy->digest_size = self->digest_size;
    memcpy(&copy->hasher, &self->hasher, sizeof(blake3_hasher));
    return (PyObject *)copy;
}

static PyMethodDef Blake3_methods[] = {
    {"update",    (PyCFunction)Blake3_update,    METH_O, NULL},
    {"digest",    (PyCFunction)Blake3_digest,    METH_VARARGS|METH_KEYWORDS, NULL},
    {"hexdigest", (PyCFunction)Blake3_hexdigest, METH_VARARGS|METH_KEYWORDS, NULL},
    {"copy",      (PyCFunction)Blake3_copy,      METH_NOARGS, NULL},
    {NULL}
};

PyDoc_STRVAR(Blake3_doc,
"BLAKE3 hash object (native implementation)\n\n"
"Methods:\n"
"  update(data)          Feed more data\n"
"  digest([length])      Return raw digest (default 32 bytes)\n"
"  hexdigest([length])   Return hex-encoded digest\n"
"  copy()                Return independent copy of current state");

static PyTypeObject Blake3_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name      = "_blake3.BLAKE3",
    .tp_doc       = Blake3_doc,
    .tp_basicsize = sizeof(Blake3Object),
    .tp_flags     = Py_TPFLAGS_DEFAULT,
    .tp_dealloc   = (destructor)Blake3_dealloc,
    .tp_methods   = Blake3_methods,
    .tp_new       = blake3_new,
};

/* Module-level derive_key (KDF-style) */

static PyObject *
blake3_derive_key(PyObject *module, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key_material", "context", "length", NULL};
    Py_buffer key_mat = {0}, ctx = {0};
    Py_ssize_t length = BLAKE3_DEFAULT_DIGEST_SIZE;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y*y*|n:derive_key", kwlist,
                                     &key_mat, &ctx, &length))
        return NULL;

    if (length < 1 || length > 65536) {
        PyErr_SetString(PyExc_ValueError, "length must be 1–65536");
        goto cleanup;
    }

    if (ctx.len == 0 || ctx.buf == NULL) {
        PyErr_SetString(PyExc_ValueError, "context must be non-empty bytes");
        goto cleanup;
    }

    PyObject *result = PyBytes_FromStringAndSize(NULL, length);
    if (!result)
        goto cleanup;

    blake3_hasher hasher;

    // Correct: use ctx.buf directly (cast to const char*)
    blake3_hasher_init_derive_key(&hasher, (const char *)ctx.buf);

    blake3_hasher_update(&hasher,
                         (const uint8_t *)key_mat.buf,
                         (size_t)key_mat.len);

    blake3_hasher_finalize_seek(&hasher, 0,
                                (uint8_t *)PyBytes_AS_STRING(result),
                                (size_t)length);

cleanup:
    if (key_mat.obj) PyBuffer_Release(&key_mat);
    if (ctx.obj)    PyBuffer_Release(&ctx);
    return result;
}

static PyMethodDef _blake3_methods[] = {
    {"blake3",     (PyCFunction)blake3_new, METH_VARARGS|METH_KEYWORDS,
     "blake3(data=b'', *, digest_size=32, key=None, usedforsecurity=False) -> BLAKE3 object"},
    {"derive_key", (PyCFunction)blake3_derive_key, METH_VARARGS|METH_KEYWORDS,
     "derive_key(key_material, context, length=32) -> derived key bytes"},
    {NULL}
};

static struct PyModuleDef _blake3module = {
    PyModuleDef_HEAD_INIT,
    .m_name   = "_blake3",
    .m_doc    = "Native BLAKE3 hash function",
    .m_size   = -1,
    .m_methods = _blake3_methods,
};

PyMODINIT_FUNC
PyInit__blake3(void)
{
    PyObject *m;
    if (PyType_Ready(&Blake3_Type) < 0)
        return NULL;
    m = PyModule_Create(&_blake3module);
    if (!m)
        return NULL;
    Py_INCREF(&Blake3_Type);
    if (PyModule_AddObject(m, "BLAKE3", (PyObject *)&Blake3_Type) < 0) {
        Py_DECREF(&Blake3_Type);
        Py_DECREF(m);
        return NULL;
    }
    return m;
}
