// CWE: CWE-1191
module insecure_debug_interface(
    input wire clk,
    input wire rst,
    input wire [31:0] data_in,
    output wire [31:0] data_out,
    input wire [3:0] control,
    input wire debug_enable,
    output wire [31:0] debug_data
);

reg [31:0] internal_reg;
reg [31:0] debug_reg;

always @(posedge clk or posedge rst) begin
    if (rst) begin
        internal_reg <= 32'h0;
        debug_reg <= 32'h0;
    end else begin
        case (control)
            4'b0001: internal_reg <= data_in;
            4'b0010: internal_reg <= internal_reg + data_in;
            4'b0100: internal_reg <= internal_reg - data_in;
            4'b1000: internal_reg <= internal_reg ^ data_in;
            default: internal_reg <= internal_reg;
        endcase
        debug_reg <= internal_reg; // Debug register mirrors internal state
    end
end

assign data_out = internal_reg;
assign debug_data = debug_enable ? debug_reg : 32'h0;

endmodule