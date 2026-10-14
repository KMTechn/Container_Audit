"""Preserve Python button results before Tk converts them through Tcl."""


class _CallbackResult:
    def __init__(self, callback):
        self.callback = callback
        self.executed = False
        self.value = None

    def __call__(self, *args):
        value = self.callback(*args)
        self.value = value
        self.executed = True
        return value


def wrap_button_callback(widget, callback):
    result = _CallbackResult(callback)
    widget._ca_callback_result = result
    return result


def bind_button_callback(widget, callback):
    widget.configure(command=wrap_button_callback(widget, callback))
    return widget


def invoke_button_callback(widget):
    result = getattr(widget, "_ca_callback_result", None)
    if isinstance(result, _CallbackResult):
        result.executed = False
        result.value = None
    widget.invoke()  # Return value belongs to Tcl, not the Python operation.
    return result.value if isinstance(result, _CallbackResult) and result.executed else None
