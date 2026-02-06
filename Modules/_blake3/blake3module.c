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


/*
 * _blake3 — BLAKE3 hash module for CPython (portable-only version)
 *
 * This version forces the use of the pure C implementation by disabling
 * all SIMD paths (SSE2, SSE4.1, AVX2, AVX512). This prevents the import
 * errors caused by CPU feature mismatches on some systems.
 */

#define PY_SSIZE_T_CLEAN
#include "Python.h"

/* Force portable C backend only */
#define BLAKE3_NO_SSE2   1
#define BLAKE3_NO_SSE41  1
#define BLAKE3_NO_AVX2   1
#define BLAKE3_NO_AVX512 1

#include "impl/blake3.h"

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
    static char *kwlist[] = {"data", "digest_size", "key", NULL};
    PyObject *data = NULL, *key = NULL;
    Py_ssize_t digest_size = BLAKE3_DEFAULT_DIGEST_SIZE;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|On$O:blake3",
                                     kwlist, &data, &digest_size, &key))
        return NULL;

    if (digest_size < 1 || digest_size > 65536) {
        PyErr_SetString(PyExc_ValueError, "digest_size must be 1–65536");
        return NULL;
    }

    Blake3Object *self = (Blake3Object *)type->tp_alloc(type, 0);
    if (!self)
        return NULL;

    self->digest_size = digest_size;

    if (key != NULL && key != Py_None) {
        Py_buffer kbuf;
        if (PyObject_GetBuffer(key, &kbuf, PyBUF_SIMPLE) < 0 ||
            kbuf.len != BLAKE3_KEY_LEN) {
            PyErr_Format(PyExc_ValueError,
                         "key must be exactly %d bytes",
                         BLAKE3_KEY_LEN);
            if (kbuf.obj) PyBuffer_Release(&kbuf);
            Py_DECREF(self);
            return NULL;
        }
        blake3_hasher_init_keyed(&self->hasher, (const uint8_t *)kbuf.buf);
        PyBuffer_Release(&kbuf);
    } else {
        blake3_hasher_init(&self->hasher);
    }

    if (data && data != Py_None) {
        Py_buffer vbuf;
        if (PyObject_GetBuffer(data, &vbuf, PyBUF_SIMPLE) == 0) {
            blake3_hasher_update(&self->hasher, vbuf.buf, vbuf.len);
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

    blake3_hasher_update(&self->hasher, view.buf, view.len);
    PyBuffer_Release(&view);

    Py_RETURN_NONE;
}

static PyObject *
Blake3_digest(Blake3Object *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"length", NULL};
    Py_ssize_t length = self->digest_size;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "|n:digest", kwlist, &length))
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
                                length);
    return result;
}

static PyObject *
Blake3_hexdigest(Blake3Object *self, PyObject *args, PyObject *kwds)
{
    PyObject *digest = Blake3_digest(self, args, kwds);
    if (!digest)
        return NULL;

    Py_ssize_t len = PyBytes_GET_SIZE(digest);
    const uint8_t *buf = (uint8_t *)PyBytes_AS_STRING(digest);

    char *hexbuf = PyMem_Malloc(len * 2 + 1);
    if (!hexbuf) {
        Py_DECREF(digest);
        return PyErr_NoMemory();
    }

    for (Py_ssize_t i = 0; i < len; i++)
        snprintf(hexbuf + i * 2, 3, "%02x", buf[i]);

    PyObject *hex = PyUnicode_FromString(hexbuf);
    PyMem_Free(hexbuf);
    Py_DECREF(digest);

    return hex;
}

static PyObject *
Blake3_copy(Blake3Object *self, PyObject *Py_UNUSED(ignored))
{
    Blake3Object *copy =
        (Blake3Object *)Blake3_Type.tp_alloc(&Blake3_Type, 0);

    if (!copy)
        return NULL;

    memcpy(&copy->hasher, &self->hasher, sizeof(blake3_hasher));
    copy->digest_size = self->digest_size;

    return (PyObject *)copy;
}

static PyMethodDef Blake3_methods[] = {
    {"update",    (PyCFunction)Blake3_update,    METH_O, NULL},
    {"digest",    (PyCFunction)Blake3_digest,
                  METH_VARARGS|METH_KEYWORDS, NULL},
    {"hexdigest", (PyCFunction)Blake3_hexdigest,
                  METH_VARARGS|METH_KEYWORDS, NULL},
    {"copy",      (PyCFunction)Blake3_copy,      METH_NOARGS, NULL},
    {NULL}
};

PyDoc_STRVAR(Blake3_doc, "BLAKE3 hash object (portable backend)");

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

static PyObject *
blake3_derive_key(PyObject *module, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key_material", "context", "length", NULL};
    Py_buffer key_mat = {0}, ctx = {0};
    Py_ssize_t length = BLAKE3_DEFAULT_DIGEST_SIZE;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "y*y*|n:derive_key", kwlist,
                                     &key_mat, &ctx, &length))
        return NULL;

    if (length < 1 || length > 65536) {
        PyErr_SetString(PyExc_ValueError,
                        "length must be 1–65536");
        goto cleanup;
    }

    if (ctx.len == 0) {
        PyErr_SetString(PyExc_ValueError,
                        "context must be non-empty bytes");
        goto cleanup;
    }

    PyObject *result = PyBytes_FromStringAndSize(NULL, length);
    if (!result)
        goto cleanup;

    char *ctx_str = PyMem_Malloc(ctx.len + 1);
    if (!ctx_str) {
        PyErr_NoMemory();
        Py_DECREF(result);
        result = NULL;
        goto cleanup;
    }

    memcpy(ctx_str, ctx.buf, ctx.len);
    ctx_str[ctx.len] = '\0';

    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, ctx_str);
    PyMem_Free(ctx_str);

    blake3_hasher_update(&hasher,
                         key_mat.buf,
                         key_mat.len);

    blake3_hasher_finalize_seek(&hasher, 0,
                                (uint8_t *)PyBytes_AS_STRING(result),
                                length);

cleanup:
    if (key_mat.obj) PyBuffer_Release(&key_mat);
    if (ctx.obj) PyBuffer_Release(&ctx);
    return result;
}

static PyMethodDef _blake3_methods[] = {
    {"blake3",     (PyCFunction)blake3_new,
                   METH_VARARGS|METH_KEYWORDS,
                   "blake3(data=b'', *, digest_size=32, key=None)"},
    {"derive_key", (PyCFunction)blake3_derive_key,
                   METH_VARARGS|METH_KEYWORDS,
                   "derive_key(key_material, context, length=32)"},
    {NULL}
};

static struct PyModuleDef _blake3module = {
    PyModuleDef_HEAD_INIT,
    .m_name   = "_blake3",
    .m_doc    = "Portable BLAKE3 implementation (no SIMD)",
    .m_size   = -1,
    .m_methods = _blake3_methods,
};

PyMODINIT_FUNC
PyInit__blake3(void)
{
    if (PyType_Ready(&Blake3_Type) < 0)
        return NULL;

    PyObject *m = PyModule_Create(&_blake3module);
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
