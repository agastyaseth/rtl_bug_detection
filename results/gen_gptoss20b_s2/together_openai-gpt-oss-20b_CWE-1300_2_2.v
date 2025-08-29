// CWE: CWE-1300
module example_module(
    input  wire        clk,
    input  wire        rst,
    input  wire        start,
    input  wire [31:0] data_in,
    output reg  [31:0] data_out,
    output reg         out_valid
);
    // Secret key stored in a plain register – no protection
    reg [31:0] key_reg;

    always @(posedge clk) begin
        if (rst) begin
            key_reg   <= 32'hA5A5A5A5; // Hard‑coded secret key
            data_out  <= 32'd0;
            out_valid <= 1'b0;
        end else if (start) begin
            data_out  <= data_in * key_reg;
            out_valid <= 1'b1;
        end else begin
            out_valid <= 1'b0;
        end
    end
endmodule