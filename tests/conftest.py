import os
import tempfile

os.environ["ROUTELEARN_DATA_DIR"] = tempfile.mkdtemp(prefix="routelearn-test-")
