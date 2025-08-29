// CWE: CWE-226
module sensitive_data_handler(
    input wire clk,
    input wire reset,
    input wire [127:0] sensitive_data,
    input wire process_enable,
    output reg [127:0] processed_data
);

    reg [127:0] internal_buffer;
    reg [127:0] temp_storage;
    reg process_done;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            internal_buffer <= 128'b0;
            temp_storage <= 128'b0;
            process_done <= 1'b0;
        end else if (process_enable) begin
            internal_buffer <= sensitive_data;
            temp_storage <= internal_buffer; // Vulnerability: sensitive data copied without clearing
            process_done <= 1'b1;
        end else if (process_done) begin
            processed_data <= temp_storage; // Outputting sensitive data without clearing
            process_done <= 1'b0;
        end
    end

endmodule