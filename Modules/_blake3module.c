/* Modules/_blake3module.c
 *
 * Native BLAKE3 implementation for CPython (corrected & hardened)
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

/* ------------------------------------------------------------------------- */
/* Constructor */
/* ------------------------------------------------------------------------- */

static PyObject *
blake3_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"data", "digest_size", "key",
                             "usedforsecurity", NULL};

    PyObject *data = NULL, *key = NULL, *usedforsecurity = NULL;
    Py_ssize_t digest_size = BLAKE3_DEFAULT_DIGEST_SIZE;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "|y*n$y*p:blake3",
                                     kwlist,
                                     &data,
                                     &digest_size,
                                     &key,
                                     &usedforsecurity))
        return NULL;

    if (digest_size < 1 || digest_size > 65536) {
        PyErr_SetString(PyExc_ValueError,
                        "digest_size must be 1-65536");
        return NULL;
    }

    Blake3Object *self = (Blake3Object *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;

    self->digest_size = digest_size;

    /* Keyed mode */
    if (key && key != Py_None) {
        Py_buffer kbuf = {0};
        if (PyObject_GetBuffer(key, &kbuf, PyBUF_SIMPLE) < 0 ||
            kbuf.len != BLAKE3_KEY_LEN) {

            PyErr_Format(PyExc_ValueError,
                         "key must be exactly %d bytes",
                         BLAKE3_KEY_LEN);

            if (kbuf.obj)
                PyBuffer_Release(&kbuf);

            Py_DECREF(self);
            return NULL;
        }

        blake3_hasher_init_keyed(&self->hasher,
                                 (const uint8_t *)kbuf.buf);
        PyBuffer_Release(&kbuf);

    } else {
        blake3_hasher_init(&self->hasher);
    }

    /* Initial data */
    if (data && data != Py_None) {
        Py_buffer vbuf = {0};
        if (PyObject_GetBuffer(data, &vbuf, PyBUF_SIMPLE) < 0) {
            Py_DECREF(self);
            return NULL;
        }
        blake3_hasher_update(&self->hasher,
                             vbuf.buf,
                             (size_t)vbuf.len);
        PyBuffer_Release(&vbuf);
    }

    return (PyObject *)self;
}

/* ------------------------------------------------------------------------- */
/* Destructor */
/* ------------------------------------------------------------------------- */

static void
Blake3_dealloc(Blake3Object *self)
{
    Py_TYPE(self)->tp_free((PyObject *)self);
}

/* ------------------------------------------------------------------------- */
/* update() */
/* ------------------------------------------------------------------------- */

static PyObject *
Blake3_update(Blake3Object *self, PyObject *arg)
{
    Py_buffer view = {0};
    if (PyObject_GetBuffer(arg, &view, PyBUF_SIMPLE) < 0)
        return NULL;

    blake3_hasher_update(&self->hasher,
                         view.buf,
                         (size_t)view.len);

    PyBuffer_Release(&view);
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */
/* digest() */
/* ------------------------------------------------------------------------- */

static PyObject *
Blake3_digest(Blake3Object *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"length", NULL};
    Py_ssize_t length = self->digest_size;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "|n:digest",
                                     kwlist, &length))
        return NULL;

    if (length <= 0) {
        PyErr_SetString(PyExc_ValueError,
                        "length must be positive");
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

/* ------------------------------------------------------------------------- */
/* hexdigest() */
/* ------------------------------------------------------------------------- */

static PyObject *
Blake3_hexdigest(Blake3Object *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"length", NULL};
    Py_ssize_t length = self->digest_size;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "|n:hexdigest",
                                     kwlist, &length))
        return NULL;

    if (length <= 0) {
        PyErr_SetString(PyExc_ValueError,
                        "length must be positive");
        return NULL;
    }

    PyObject *digest = Blake3_digest(self, args, kwds);
    if (!digest)
        return NULL;

    Py_ssize_t digest_len = PyBytes_GET_SIZE(digest);
    const unsigned char *bytes =
        (const unsigned char *)PyBytes_AS_STRING(digest);

    PyObject *hex = PyUnicode_New(digest_len * 2, 0x66);
    if (!hex) {
        Py_DECREF(digest);
        return NULL;
    }

    Py_ssize_t pos = 0;
    for (Py_ssize_t i = 0; i < digest_len; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", bytes[i]);

        if (PyUnicode_WriteChar(hex, pos++, buf[0]) < 0 ||
            PyUnicode_WriteChar(hex, pos++, buf[1]) < 0) {

            Py_DECREF(hex);
            Py_DECREF(digest);
            return NULL;
        }
    }

    Py_DECREF(digest);
    return hex;
}

/* ------------------------------------------------------------------------- */
/* copy() */
/* ------------------------------------------------------------------------- */

static PyObject *
Blake3_copy(Blake3Object *self, PyObject *Py_UNUSED(ignored))
{
    Blake3Object *copy =
        (Blake3Object *)Blake3_Type.tp_alloc(&Blake3_Type, 0);
    if (!copy)
        return NULL;

    copy->digest_size = self->digest_size;
    memcpy(&copy->hasher, &self->hasher, sizeof(blake3_hasher));
    return (PyObject *)copy;
}

/* ------------------------------------------------------------------------- */
/* __repr__ */
/* ------------------------------------------------------------------------- */

static PyObject *
Blake3_repr(Blake3Object *self)
{
    return PyUnicode_FromFormat(
        "<BLAKE3 hash object at %p>",
        self);
}

/* ------------------------------------------------------------------------- */
/* derive_key() */
/* ------------------------------------------------------------------------- */

static PyObject *
blake3_derive_key(PyObject *module, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key_material", "context", "length", NULL};

    Py_buffer key_mat = {0};
    Py_buffer ctx = {0};
    Py_ssize_t length = BLAKE3_DEFAULT_DIGEST_SIZE;
    PyObject *result = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "y*y*|n:derive_key",
                                     kwlist,
                                     &key_mat, &ctx, &length))
        return NULL;

    if (length < 1 || length > 65536) {
        PyErr_SetString(PyExc_ValueError,
                        "length must be 1-65536");
        goto cleanup;
    }

    if (ctx.len == 0 || ctx.buf == NULL) {
        PyErr_SetString(PyExc_ValueError,
                        "context must be non-empty bytes");
        goto cleanup;
    }

    result = PyBytes_FromStringAndSize(NULL, length);
    if (!result)
        goto cleanup;

    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, (const char *)ctx.buf);

    blake3_hasher_update(&hasher,
                         (const uint8_t *)key_mat.buf,
                         (size_t)key_mat.len);

    blake3_hasher_finalize_seek(&hasher, 0,
                                (uint8_t *)PyBytes_AS_STRING(result),
                                (size_t)length);

cleanup:
    if (key_mat.obj)
        PyBuffer_Release(&key_mat);
    if (ctx.obj)
        PyBuffer_Release(&ctx);

    return result;
}

/* ------------------------------------------------------------------------- */
/* Method tables */
/* ------------------------------------------------------------------------- */

static PyMethodDef Blake3_methods[] = {
    {"update",    (PyCFunction)Blake3_update, 
                  METH_O, NULL},
    {"digest",    (PyCFunctionWithKeywords)Blake3_digest, 
                  METH_VARARGS | METH_KEYWORDS, NULL},
    {"hexdigest", (PyCFunctionWithKeywords)Blake3_hexdigest, 
                  METH_VARARGS | METH_KEYWORDS, NULL},
    {"copy",      (PyCFunction)Blake3_copy, 
                  METH_NOARGS, NULL},
    {NULL}
};

static PyMethodDef _blake3_methods[] = {
    {"blake3",     (PyCFunctionWithKeywords)blake3_new,
                   METH_VARARGS | METH_KEYWORDS,
                   "blake3(data=b'', *, digest_size=32, key=None, usedforsecurity=False) -> BLAKE3 object"},
    {"derive_key", (PyCFunctionWithKeywords)blake3_derive_key,
                   METH_VARARGS | METH_KEYWORDS,
                   "derive_key(key_material, context, length=32) -> derived key bytes"},
    {NULL}
};

/* ------------------------------------------------------------------------- */
/* Module definition */
/* ------------------------------------------------------------------------- */

static struct PyModuleDef _blake3module = {
    PyModuleDef_HEAD_INIT,
    .m_name    = "_blake3",
    .m_doc     = "Native BLAKE3 hash function",
    .m_size    = -1,
    .m_methods = _blake3_methods,
};

/* ------------------------------------------------------------------------- */
/* Module init */
/* ------------------------------------------------------------------------- */

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
    if (PyModule_AddObject(m, "BLAKE3",
                           (PyObject *)&Blake3_Type) < 0) {
        Py_DECREF(&Blake3_Type);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}
