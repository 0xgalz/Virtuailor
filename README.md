# Virtuailor - IDAPython tool for C++ vtables reconstruction 


Virtuailor is an IDAPython tool that reconstructs vtables for C++ code written for intel architecture and both 32bit and 64bit code.
The tool constructed from 2 parts, static and dynamic.

The first is the static part, contains the following capabilities:
* Detects indirect calls.
* Hooks the value assignment of the indirect calls using conditional breakpoints (the hook code). 

The second is the dynamic part, contains the following capabilities:
* Creates vtable structures. 
* Rename functions and vtables addresses.
* Add structure offset to the assembly indirect calls. 
* Add xref from indirect calls to their virtual functions(multiple xrefs).

## How to Use?

1. By default Virtuailor will look for virtual calls in ALL the addresses in the code.
If you want to limit the code only for specific address range, no problem, just edit the *Main* file to add the range you want to target in the variables start_addr_range and end_addr_range:

```python
if __name__ == '__main__':

    start_addr_range = idc.MinEA()  # You can change the virtual calls address range
    end_addr_range = idc.MaxEA()
    add_bp_to_virtual_calls(start_addr_range, end_addr_range)
```

2. Optional, (but extremely recommended), create a snapshot of your idb. Just press ctrl+shift+t and create a snapshot.

3. Press File->Run script... then go to Virtuailor folder and choose to run Main.py, You can see the following gif for a more clear and visual explanation.
![How to use](https://github.com/0xgalz/Virtuailor/blob/master/Images/howto.gif)

Now the breakpoints has been placed in your code and all you have to do is to run your code with IDA debugger, do whatever actions you want and see how the vtables is being built! 

In case you don't want/need the breakpoints anymore just go to the breakpoint list tab in IDA and delete the breakpoints as you like.

It is also really important for me to note that this is the first version of the tool with both 32 anf 64 bit support, probably in some cases a small amount of breakpoints will be missed, in these cases please open an issue and contact me so I will be able to improve the code and help fixing it. Thank you in advanced for that :)

## Output and General Functions

#### vtables structures
The structures Virtuailor creates from the vtable used in virtual call that were hit. The vtable functions are extracted from the memory based on the relevant register that was used in the BP opcode.

![vtable example](https://github.com/0xgalz/Virtuailor/blob/master/Images/vtable_structure.png)
Since I wanted to create a correlation between the structure in IDA and the vtables in the data section, the BP changes the vtable address name in the data section to the name of the structure. As you can see in the following picture:
![vtable example](https://github.com/0xgalz/Virtuailor/blob/master/Images/vtable_in_memory.png)

The virtual functions names are also being changed, take aside situations where the names are not the default IDA names (functions with symbols or functions that the user changed) in those cases the function names will stay the same and will also be add to the vtable structure with their current name.

The chosen names is constructed using the following pattern: 
* vtable_ 
* vfunc_
the rest of the name is either offset from the beginning of the Segment, this is mostly because most binaries nowadays are PIE and PIC and thus ASLR is enforced, (instead of using the full address name, which is also quite long on 64bit environments).
The vtable structure also has a comment, "Was called from offset: XXXX", this offset is the offset from the beginning of the Segment.

#### Adding Structures to the Assembly

After creating the vtable Virtuailor also adds a connection between the structure created and the assembly as you can see in the following images:
![BP after an execution, Example 2](https://github.com/0xgalz/Virtuailor/blob/master/Images/stroff2.png)

P.S: The structure offset used in the BP is only relevant for the last call that was made, in order to get a better understanding of all the virtual calls that were made the xref feature was added as explained in the next section

#### Xref to virtual functions

When reversing C++ statically it is not trivial to see who called who, this is because most calls are indirect calls, however after running Virtuailor every function that was called indirectly now has an xref to those locations.

The following gif shows the added Xrefs with their indirect function call:

![xref](https://github.com/0xgalz/Virtuailor/blob/master/Images/xref.gif)

## Former talks and lectures 

The tool was presented in RECon brussels, Troopers and Warcon. 
The presentation could be found in the following link: https://www.youtube.com/watch?v=Xk75TM7NmtA

## Thanks

REcon Brussels, Troopers, Warcon crews, Nana, @tmr232, @matalaz, @oryandp, @talkain, @shiftreduce


## License

The plugin is licensed under the GNU GPL v3 license.
