// CWE: CWE-441
module proxy_intermediary #(parameter WIDTH = 32)
(
    input wire clk,
    input wire reset_n,
    input wire [WIDTH-1:0] data_in,
    input wire data_in_valid,
    output wire [WIDTH-1:0] data_out,
    output wire data_out_valid
);

    reg [WIDTH-1:0] buffer;
    reg buffer_valid;

    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            buffer <= {WIDTH{1'b0}};
            buffer_valid <= 1'b0;
        end else if (data_in_valid) begin
            buffer <= data_in;
            buffer_valid <= 1'b1;
        end
    end

    // Unintended proxy: forwards data from buffer without proper authorization check
    assign data_out = buffer;
    assign data_out_valid = buffer_valid;

endmodule