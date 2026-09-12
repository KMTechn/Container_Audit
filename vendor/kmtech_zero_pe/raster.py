"""Container_Audit compatibility facade for the pinned shared raster core.

PNG writes in the product remain admitted by phs_label_workflow._save_raster_png.
Image-producing operations retain this facade class through the core factories.
"""
from kmtech_shared import raster as _core
from kmtech_shared.raster import (
    Anchor, BITMAPINFO, BITMAPINFOHEADER, Color, FontSpec, GdiRenderError,
    MAX_PNG_INPUT_BYTES, MAX_RASTER_PIXELS, RGBQUAD, RasterError, Resample,
    SIZE, bitmap_info,
)


class RasterImage(_core.RasterImage):
    """CA image identity with the shared decode, resize and PNG implementation."""


class RasterCanvas(_core.RasterCanvas):
    """Return CA images from the shared GDI canvas."""

    image_class = RasterImage
