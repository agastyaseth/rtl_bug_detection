// CWE: CWE-1191
module vulnerable_debug_interface(
    input wire clk,
    input wire rst,
    input wire [31:0] data_in,
    output wire [31:0] data_out,
    input wire debug_enable,
    output wire [31:0] debug_data
);

reg [31:0] internal_reg;

// Assign debug_data without proper access control
assign debug_data = debug_enable ? internal_reg : 32'h0;

always @(posedge clk or posedge rst) begin
    if (rst) begin
        internal_reg <= 32'h0;
    end else begin
        internal_reg <= data_in;
    end
end

assign data_out = internal_reg;

endmodule