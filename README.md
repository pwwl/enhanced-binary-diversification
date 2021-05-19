# Malware Makeover

This repo contains the binary-randomization code discussed in our AsiaCCS
2021 paper. Our code provides several extensions and fixes to the open-source
implementation that accompanied Pappas et al.'s in-place randomization and Koo
and Polychronakis' code-displacement work (see references below). These include,
but are not limited to, the ability to compose several transformations in one
run, fixes to memory leaks, and support to new instructions. We would also like 
to thank Michael Stroucken for helping find and fix memory leaks in pydasm and 
ORP.


The code is available under the MIT Open Source License, along with the
licenses of our dependencies:

* [In-place randomization](https://github.com/vpappas/orp) - Copyright (c) 2012, Vasilis Pappas
* [Code displacement](https://github.com/kevinkoo001/ropf) - Copyright (c) 2015 Hyungjoon Koo

**Note**: We decided *not* to open source the part of the code that produces
evasive malware variants due to concerns about potential misuse, especially 
since no effective defense is known to date (see paper). For any related 
questions, please reach out to us via email.


## How to run

It is easiest to run the code using Docker. Having installed Docker, run the
following command to deploy a transient container (the first run might take
several minutes to finish execution):

`python deploy.py`

To randomize a binary, you should run the `binary_transform.py` script
from within the container. As an example, we've included the original
binary of `caffeine.exe`---a program that prevents the operating
system from sleeping---in this repo. To randomize this binary, run

`python binary_transform.py --pe example/caffeine.exe `

This would output another executable that should have the same
functionality, but different bytes. If you want to run multiple
iterations of randomization (e.g., 10), you can run  

`python binary_transform.py --pe example/caffeine.exe --iters 10`

To randomize a new binary you need to extract its control-flow graph using
IDA Pro first. To that end, you need to run the `orp.py` script provided by
Pappas et al. (also found under `enhanced-binary-randomization/orp/`) with
the `-d` option. Please refer to
`enhanced-binary-randomization/orp/README-Pappas.txt` for further details.

## References

If you use any of the code found in this repo, please consider citing
the following papers:

```
@inproceedings{Pappas2012,
  title={Smashing the gadgets: Hindering return-oriented programming using in-place code randomization},
  author={Pappas, Vasilis and Polychronakis, Michalis and Keromytis, Angelos D},
  booktitle={IEEE Symposium on Security and Privacy},
  year={2012}
}

@inproceedings{Koo2016,
  title={Juggling the gadgets: Binary-level code randomization using instruction displacement},
  author={Koo, Hyungjoon and Polychronakis, Michalis},
  booktitle={Asia Conference on Computer and Communications Security (AsiaCCS)},
  year={2016}
}

@inproceedings{Lucas21,
  title={Malware makeover: Breaking ML-based static analysis by modifying executable bytes},
  author={Keane Lucas and Mahmood Sharif and Lujo Bauer and Michael K. Reiter and Saurabh Shintre},
  booktitle={Asia Conference on Computer and Communications Security (AsiaCCS)},
  year={2021}
}
```

## Collaborators

* Keane Lucas (keanelucas@cmu.edu)
* Mahmood Sharif (mahmoods@alumni.cmu.edu)
* Lujo Bauer (lbauer@cmu.edu)
* Michael K. Reiter (michael.reiter@duke.edu)
* Saurabh Shintre (saurabh.shintre@nortonlifelock.com)