// CWE: CWE-1191
module debug_interface(
    input wire clk,
    input wire rst,
    input wire enable,
    input wire [31:0] data_in,
    output wire [31:0] data_out,
    output wire [31:0] debug_data
);

reg [31:0] internal_reg;
reg [31:0] debug_reg;

// Internal logic
always @(posedge clk or posedge rst) begin
    if (rst) begin
        internal_reg <= 32'h0;
        debug_reg <= 32'h0;
    end else if (enable) begin
        internal_reg <= data_in;
        debug_reg <= internal_reg; // Improper access control
    end
end

assign data_out = internal_reg;
assign debug_data = debug_reg;

endmodule