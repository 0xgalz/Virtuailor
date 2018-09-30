# This is the breakpoint condition code.
# Every value inside the <<< >>> is an argument
# The arguments are:
#    * start_addr -> The virtual call address
#    * register_vtable -> The register who points to the vtable
#    * offset -> The offset of the relevant function from the vtable base pointer

virtual_call_addr = + str(<<<start_addr>>>)  #idc.NextHead(idc.here())

# Get the adresses of the  vtable and the virtual function from the relevant register:
p_vtable_addr = idc.GetRegValue("<<<register_vtable>>>")
pv_func_addr = idc.GetRegValue("<<<register_vtable>>>") + <<<offset>>>
v_func_addr = get_wide_dword(pv_func_addr)

# calculate the offset of the virtual function from the beginning of its section, determine its name
# in case the function name was changed by the user the name will stay the same
v_func_name = GetFunctionName(v_func_addr)
if v_func_name[:4] == "sub_":
    v_func_name =  "vfunc_" + "__" + str(v_func_name) # str(hex(v_func_addr- SegStart(v_func_addr))) the name will be the offset from the beginning of the segment
print v_func_name

# create the vtable struct and calculate the offset of the vtable from the beginning of its section, determine its name
#calc_struct_name =  int(p_vtable_addr) - SegStart(p_vtable_addr)
struct_name = "vtable_" + str(p_vtable_addr) #str(calc_struct_name)

#change vtable address name
#idaapi.set_name(p_vtable_addr, struct_name, idaapi.SN_FORCE)

struct_id = add_struc(-1, struct_name, 0)
print struct_id, struct_name
if struct_id != 4294967295: # checks if the struct creation succeeded
    # add structure members and change the offset structure in the assembly
    idc.add_struc_member(struct_id, v_func_name, <<<offset>>> , FF_DWRD, -1, 4)
    idc.SetMemberComment(struct_id, """ + offset + """ , "Was called form address:" + str(hex(idc.GetRegValue("eip"))) , 1)
    print "%%%%structure_id%%%%", struct_id #idc.GetRegValue("eip")
    idc.OpStroff(idautils.DecodeInstruction(int(idc.GetRegValue("eip"))), 1, struct_id)

    #add comments to the assembly
    last_text = idc.get_cmt(virtual_call_addr, 1)
    if last_text == None:
        last_text = ""
    idc.set_cmt(virtual_call_addr, last_text + "vtable struct is: " +idaapi.get_struc_name(struct_id) + ", function: " + v_func_name, 1)
1 == 1