// CWE: CWE-203
module secure_comparator (
    input wire [7:0] secret_key,
    input wire [7:0] input_data,
    output reg match
);

    reg [7:0] temp_key;
    reg [7:0] temp_data;

    always @(*) begin
        temp_key = secret_key;
        temp_data = input_data;
        match = 0;
        
        if (temp_key[0] == 1'b1) begin
            #1; // Introduce delay if the LSB of the key is 1
        end

        if (temp_key == temp_data) begin
            match = 1;
        end
    end

endmodule