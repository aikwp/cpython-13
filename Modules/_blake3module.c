/* Modules/_blake3module.c
 *
 * Native BLAKE3 implementation for CPython (corrected & hardened)
 */

#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include "structmember.h"
#include "_blake3/blake3.h"

/* =========================================================
 * Blake3Object: Python wrapper for official BLAKE3 C hasher
 * ========================================================= */

typedef struct {
    PyObject_HEAD
    blake3_hasher hasher;   /* official BLAKE3 hasher state */
    Py_ssize_t digest_size; /* requested output size */
    int finalized;          /* 1 if digest() has been called */
} Blake3Object;

/* -------------------- Helper Functions -------------------- */

/* Check that a Python object is bytes */
static int
check_bytes(PyObject *obj, const char *argname) {
    if (!PyBytes_Check(obj)) {
        PyErr_Format(PyExc_TypeError, "%s must be bytes", argname);
        return 0;
    }
    return 1;
}

/* -------------------- Object Initialization -------------------- */

static int
Blake3_init(Blake3Object *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = {"data", "digest_size", NULL};

    PyObject *data = NULL;
    Py_ssize_t digest_size = 32;  /* default size */

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|On", kwlist,
                                     &data, &digest_size)) {
        return -1;
    }

    if (digest_size <= 0) {
        PyErr_SetString(PyExc_ValueError, "digest_size must be > 0");
        return -1;
    }

    self->digest_size = digest_size;
    self->finalized = 0;

    blake3_hasher_init(&self->hasher);

    if (data && data != Py_None) {
        if (!check_bytes(data, "data"))
            return -1;

        blake3_hasher_update(&self->hasher,
                             (uint8_t *)PyBytes_AS_STRING(data),
                             PyBytes_GET_SIZE(data));
    }

    return 0;
}

/* -------------------- update() -------------------- */

static PyObject *
Blake3_update(Blake3Object *self, PyObject *data) {
    if (self->finalized) {
        PyErr_SetString(PyExc_ValueError, "hash object already finalized");
        return NULL;
    }

    if (!check_bytes(data, "data"))
        return NULL;

    blake3_hasher_update(&self->hasher,
                         (uint8_t *)PyBytes_AS_STRING(data),
                         PyBytes_GET_SIZE(data));

    Py_RETURN_NONE;
}

/* -------------------- digest() -------------------- */

static PyObject *
Blake3_digest(Blake3Object *self, PyObject *Py_UNUSED(ignored)) {
    PyObject *out = PyBytes_FromStringAndSize(NULL, self->digest_size);
    if (!out)
        return NULL;

    blake3_hasher_finalize(&self->hasher,
                           (uint8_t *)PyBytes_AS_STRING(out),
                           self->digest_size);

    self->finalized = 1;
    return out;
}

/* -------------------- hexdigest() -------------------- */

static PyObject *
Blake3_hexdigest(Blake3Object *self, PyObject *Py_UNUSED(ignored)) {
    PyObject *digest = Blake3_digest(self, NULL);
    if (!digest)
        return NULL;

    PyObject *hex = _Py_strhex(
        PyBytes_AS_STRING(digest),
        PyBytes_GET_SIZE(digest));

    Py_DECREF(digest);
    return hex;
}

/* -------------------- copy() -------------------- */

static PyObject *
Blake3_copy(Blake3Object *self, PyObject *Py_UNUSED(ignored)) {
    Blake3Object *newobj = PyObject_New(Blake3Object, Py_TYPE(self));
    if (!newobj)
        return NULL;

    newobj->hasher = self->hasher;  /* struct copy */
    newobj->digest_size = self->digest_size;
    newobj->finalized = self->finalized;

    return (PyObject *)newobj;
}

/* -------------------- Methods and Members -------------------- */

static PyMethodDef Blake3_methods[] = {
    {"update",    (PyCFunction)Blake3_update,    METH_O,   "Update the hash object with bytes"},
    {"digest",    (PyCFunction)Blake3_digest,    METH_NOARGS, "Return the digest as bytes"},
    {"hexdigest", (PyCFunction)Blake3_hexdigest, METH_NOARGS, "Return the digest as hexadecimal string"},
    {"copy",      (PyCFunction)Blake3_copy,      METH_NOARGS, "Return a copy of the hash object"},
    {NULL}
};

static PyMemberDef Blake3_members[] = {
    {"digest_size", T_PYSSIZET, offsetof(Blake3Object, digest_size), READONLY, "Digest size in bytes"},
    {NULL}
};

/* -------------------- Type Object -------------------- */

static PyTypeObject Blake3Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "_blake3.blake3",
    .tp_basicsize = sizeof(Blake3Object),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "BLAKE3 hash object",
    .tp_methods = Blake3_methods,
    .tp_members = Blake3_members,
    .tp_init = (initproc)Blake3_init,
    .tp_new = PyType_GenericNew,
};

/* -------------------- Module Definition -------------------- */

static PyModuleDef blake3module = {
    PyModuleDef_HEAD_INIT,
    "_blake3",
    "Python wrapper for official BLAKE3",
    -1,
};

PyMODINIT_FUNC
PyInit__blake3(void) {
    PyObject *m;

    if (PyType_Ready(&Blake3Type) < 0)
        return NULL;

    m = PyModule_Create(&blake3module);
    if (!m)
        return NULL;

    Py_INCREF(&Blake3Type);
    PyModule_AddObject(m, "blake3", (PyObject *)&Blake3Type);

    return m;
}

/* -------------------- End of _blake3module.c -------------------- */
