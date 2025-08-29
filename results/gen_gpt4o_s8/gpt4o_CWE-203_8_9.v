// CWE: CWE-203
module secure_comparator(
    input wire [7:0] secret_value,
    input wire [7:0] input_value,
    output reg match
);
    reg [7:0] temp_secret;
    reg [7:0] temp_input;
    reg delay_flag;

    always @(*) begin
        temp_secret = secret_value;
        temp_input = input_value;
        delay_flag = 1'b0;

        if (temp_secret == temp_input) begin
            match = 1'b1;
        end else begin
            match = 1'b0;
            if (temp_secret[0] == 1'b1) begin
                delay_flag = 1'b1; // Introduce delay if LSB of secret is 1
            end
        end

        if (delay_flag) begin
            #1; // Delay to create observable discrepancy
        end
    end
endmodule