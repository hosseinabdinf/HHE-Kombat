# Demo Implementation Transistor

You can launch the plain implementation of Transistor with:

```bash
pip install -r requirements.txt
cd symmetric
python3 main.py
```

For the homomorphic version, you can compile it with:
```bash
cd homomorphic_implementation/homomorphic_transistor
cargo run --release
```

The two versions are fed with the same inputs, so it is easy to see that the two versions yield the same output.


The folder `homomorphic_implementation/homomorphic_transistor` contains the high-level implementation of transistor, while `homomorphic_implementation/tfhe-rs-odd` is a fork of Zama's `tfhe-rs` supporting odd modulos. It handles the tfhe operations.