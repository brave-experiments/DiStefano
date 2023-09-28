# VHDL

This directory contains three high-level VHDL files that describe addition circuits. 
In particular:

1. ```ModAdd256.vhdl``` describes the addition of two ```256-bit``` numbers modulo ```p```, also
   represented as a 256-bit number.
2. ```ModAdd384.vhdl``` describes the addition of two ```384-bit``` numbers modulo ```p```, also
   represented as a 384-bit number.
3. ```ModAdd521.vhdl``` describes the addition of two ```521-bits``` numbers modulo ```p```, also
   represented as a 521-bit number. 

These circuits are just minor modifications of the circuit from [here](https://github.com/KULeuven-COSIC/SCALE-MAMBA/tree/master/Circuits/VHDL). We thank the SCALE-MAMBA team for making this circuit public, as well as the script for converting from Verilog to Bristol Fashion.  


## How can I turn these circuits into Bristol Fashion?

We provide these circuits in Bristol Fashion anyway, but if you want to repeat the process you 
can follow these instructions. For brevity, we give these solely for the 256-bit circuit:

1. Clone [vhd2vl](https://github.com/ldoolitt/vhd2vl) and build it using the instructions there.
2. Run ```./vhd2vl ModAdd256.vhdl ModAdd256.v``` and  to output the files as Verilog.
3. Navigate [here](https://github.com/KULeuven-COSIC/SCALE-MAMBA/tree/master/Circuits) and download
   the ```convert_yosys.py``` file.
4. Install ```yosys``` on your computer. ```yosys``` can be found in most Linux package managers.
5. Run ```python3 convert_yosys.py ModAdd256.v ModAdd256.txt``` to produce the Bristol Fashion circuit. Depending on the complexity of the circuit, this may take a while. 


   
   
