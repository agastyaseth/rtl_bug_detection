// CWE: CWE-226
module secure_data_processor (
    input wire clk,
    input wire rst,
    input wire [127:0] data_in,
    input wire [127:0] key,
    output reg [127:0] data_out
);

    reg [127:0] internal_data;
    reg [127:0] internal_key;
    reg processing_done;

    always @(posedge clk) begin
        if (rst) begin
            internal_data <= 128'b0;
            internal_key <= 128'b0;
            processing_done <= 1'b0;
        end else begin
            internal_data <= data_in ^ key;
            internal_key <= key;
            processing_done <= 1'b1;
        end
    end

    always @(posedge clk) begin
        if (processing_done) begin
            data_out <= internal_data;
            // CWE-226: Sensitive information in internal_key is not cleared
            // internal_key <= 128'b0; // This line is commented out, leaving sensitive data in internal_key
        end
    end

endmodule