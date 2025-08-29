// CWE: CWE-226
module sensitive_data_handler(
    input wire clk,
    input wire rst,
    input wire [127:0] sensitive_data_in,
    input wire process_enable,
    output reg [127:0] processed_data_out
);

    reg [127:0] internal_buffer;
    reg [127:0] temp_storage;

    always @(posedge clk) begin
        if (rst) begin
            internal_buffer <= 128'b0;
            temp_storage <= 128'b0;
            processed_data_out <= 128'b0;
        end else if (process_enable) begin
            internal_buffer <= sensitive_data_in;
            temp_storage <= internal_buffer; // Sensitive data copied to temp_storage
            processed_data_out <= temp_storage ^ 128'hA5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5; // Example processing
        end
    end

endmodule