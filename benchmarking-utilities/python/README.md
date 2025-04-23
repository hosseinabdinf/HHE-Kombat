# Python Benchmarking Utility

## How to Use

To utilize the benchmarking utility in your Python project, first move the `utils` folder into your `root` directory, and install the neccesry libraries by the following command:

```bash 
pip install -r requirements.txt
```

## Import
```
from benchmark_utils import *
```

## Example usage
```python
if __name__ == "__main__":
    def example_task():
        sum([i ** 2 for i in range(10000)])

    benchmark("Example Task", 10, example_task)
```