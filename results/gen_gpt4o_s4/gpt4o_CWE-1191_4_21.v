// CWE: CWE-1191
module insecure_debug_interface(
    input wire clk,
    input wire rst,
    input wire [7:0] data_in,
    input wire debug_enable,
    output wire [7:0] data_out,
    output wire [7:0] debug_data
);

reg [7:0] internal_reg;
reg [7:0] debug_reg;

assign data_out = internal_reg;
assign debug_data = debug_enable ? debug_reg : 8'h00;

always @(posedge clk or posedge rst) begin
    if (rst) begin
        internal_reg <= 8'h00;
        debug_reg <= 8'h00;
    end else begin
        internal_reg <= data_in;
        debug_reg <= internal_reg; // Debug register captures internal state
    end
end

endmodule