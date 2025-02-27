## ppool
process pool


### build&install
python3 setup.py sdist bdist_wheel

### demo
```
#!/usr/bin/python
# -*- coding: UTF-8 -*-

import time
import flask
import logging

from ppool import Pool
from ppool import Context

logger = logging.getLogger(__name__)

pool: Pool = None
app = flask.Flask(__name__)


# Process pool processing method
# 
# args  The parameters passed when calling correspond to the args parameters of calling the apple method.
# ctx   Process context, a process returns
def func(args=None, ctx=None):
    i = 0
    total = 0
    while i < 100000:
        total += i
        i += 1

    return "HelloWorld! -----> [{}] - {}    ctx-{}".format(
        time.time(), total, ctx.obj if ctx is not None else "None"
    )


@app.route("/test", methods=["get", "post"])
def onTest():
    # Call process pool to process data
    result = pool.apply(
        args="multiprocessing-----> called! -- [{}]".format(time.time()),
        try_times=3,
    )

    if 200 < result.cost():
        logger.info(
            "apply called timeout more than 200ms,  cost={}ms".format(result.cost())
        )

    logger.info(
        "Result code:{}   msg:{}    value:{}    cost:{}ms".format(
            result.code(), result.msg(), result.value(), result.cost()
        )
    )

    return str(result.value()) if result.value() is not None else "apply is None"


if __name__ == "__main__":
    logging.basicConfig(filename="myapp.log", level=logging.INFO)

    # Context(obj=engine)
    # Constructing a process pool object
    pool = Pool(
        amount=2,
        func=func,
        ctxs=(
            Context(obj="context1"),
            Context(obj="context2"),
            Context(obj="context3"),
        ),
        default_ctx=Context(obj="default_contex"),
    )
    app.run(host="0.0.0.0", port=8089, debug=False, threaded=True)

    pass

```