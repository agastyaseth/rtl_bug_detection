// CWE: CWE-1191
module debug_interface(
    input wire clk,
    input wire rst,
    input wire [7:0] debug_addr,
    input wire debug_enable,
    input wire [31:0] debug_data_in,
    output reg [31:0] debug_data_out,
    output reg [7:0] internal_registers [0:255]
);

    // Unsecured debug interface with full read/write access
    always @(posedge clk) begin
        if (debug_enable) begin
            // Direct access to internal registers without authentication
            internal_registers[debug_addr] <= debug_data_in;
            debug_data_out <= internal_registers[debug_addr];
        end
    end

    // No access control mechanism prevents unauthorized debug access
    // Potential vulnerability: Any entity can read/modify internal state
    // when debug_enable is asserted

endmodule